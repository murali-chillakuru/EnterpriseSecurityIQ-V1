"""
Risk evaluator — Defender for Cloud posture analysis.

Checks: disabled Defender plans, high-severity recommendations, secure score.
"""
from __future__ import annotations

import logging

from app.auth import ComplianceCredentials
from app.collectors.base import paginate_arm, AccessDeniedError
from app.risk_evaluators.finding import risk_finding as _risk_finding

log = logging.getLogger(__name__)


async def analyze_defender_posture(
    creds: ComplianceCredentials,
    subscriptions: list[dict],
    evidence_index: dict[str, list[dict]],
) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_defender_coverage(evidence_index))
    findings.extend(await _check_security_recommendations(creds, subscriptions))
    findings.extend(await _check_secure_score(creds, subscriptions))
    return findings


def _check_defender_coverage(evidence_index: dict) -> list[dict]:
    plans = evidence_index.get("azure-defender-plan", [])
    disabled: list[dict] = []

    for ev in plans:
        data = ev.get("Data", ev.get("data", {}))
        tier = data.get("PricingTier", data.get("pricing_tier", ""))
        plan_name = data.get("PlanName", data.get("plan_name",
                   data.get("Name", data.get("name", ""))))
        if tier.lower() == "free":
            disabled.append({
                "Type": "DefenderPlan", "PlanName": plan_name, "Tier": tier,
                "SubscriptionId": data.get("SubscriptionId", data.get("subscription_id", "")),
            })

    if disabled:
        plan_names = sorted({d["PlanName"] for d in disabled})
        return [_risk_finding(
            category="defender",
            subcategory="disabled_plans",
            title=f"{len(disabled)} Defender plans on Free tier",
            description=(
                f"Disabled Defender plans: {', '.join(plan_names[:10])}. "
                "Without Defender you lack threat detection and vulnerability assessment."
            ),
            severity="high",
            affected_resources=disabled,
            remediation={
                "Description": "Enable Defender for Cloud on all resource types.",
                "AzureCLI": "az security pricing create -n <plan-name> --tier Standard",
                "PowerShell": "Set-AzSecurityPricing -Name '<plan-name>' -PricingTier 'Standard'",
                "PortalSteps": [
                    "Navigate to Microsoft Defender for Cloud > Environment settings",
                    "Select subscription > Enable all Defender plans",
                ],
            },
        )]
    return []


async def _check_security_recommendations(
    creds: ComplianceCredentials, subscriptions: list[dict],
) -> list[dict]:
    try:
        from azure.mgmt.security.aio import SecurityCenter
    except ImportError:
        log.warning("azure-mgmt-security not available for recommendations")
        return []

    high_recs: list[dict] = []
    for sub in subscriptions:
        sub_id = sub.get("subscription_id", sub.get("subscriptionId", ""))
        try:
            client = SecurityCenter(creds.credential, sub_id, asc_location="centralus")
            recs = await paginate_arm(
                client.assessments.list(scope=f"/subscriptions/{sub_id}")
            )
            for rec in recs:
                status = rec.status
                if hasattr(status, "code") and status.code == "Unhealthy":
                    severity = "Unknown"
                    if hasattr(rec, "metadata") and rec.metadata:
                        severity = getattr(rec.metadata, "severity", "Unknown")
                    if severity in ("High", "high"):
                        display_name = getattr(rec, "display_name", "")
                        if not display_name and hasattr(rec, "metadata"):
                            display_name = getattr(rec.metadata, "display_name", "Unknown")
                        high_recs.append({
                            "Type": "SecurityRecommendation",
                            "Name": display_name,
                            "Severity": severity,
                            "SubscriptionId": sub_id,
                        })
        except AccessDeniedError:
            log.warning("Access denied for security assessments in sub %s", sub_id)
        except Exception as exc:
            log.warning("Security recommendations failed for sub %s: %s", sub_id, exc)

    if high_recs:
        return [_risk_finding(
            category="defender",
            subcategory="security_recommendations",
            title=f"{len(high_recs)} high-severity security recommendations",
            description="Defender for Cloud identified high-severity issues requiring investigation.",
            severity="high",
            affected_resources=high_recs[:50],
            remediation={
                "Description": "Review and address each recommendation in Defender for Cloud.",
                "PortalSteps": [
                    "Navigate to Microsoft Defender for Cloud > Recommendations",
                    "Filter by severity: High",
                    "Address each recommendation",
                ],
            },
        )]
    return []


async def _check_secure_score(
    creds: ComplianceCredentials, subscriptions: list[dict],
) -> list[dict]:
    try:
        from azure.mgmt.security.aio import SecurityCenter
    except ImportError:
        return []

    scores: list[dict] = []
    for sub in subscriptions:
        sub_id = sub.get("subscription_id", sub.get("subscriptionId", ""))
        try:
            client = SecurityCenter(creds.credential, sub_id, asc_location="centralus")
            score_list = await paginate_arm(client.secure_scores.list())
            for score in score_list:
                current = getattr(score, "current", None)
                max_score = getattr(score, "max", None)
                if current is not None and max_score:
                    cur_val = getattr(current, "score", current) if hasattr(current, "score") else current
                    max_val = getattr(max_score, "score", max_score) if hasattr(max_score, "score") else max_score
                    if isinstance(cur_val, (int, float)) and isinstance(max_val, (int, float)):
                        pct = (cur_val / max_val) * 100 if max_val > 0 else 0
                        scores.append({"SubscriptionId": sub_id, "Current": cur_val,
                                       "Max": max_val, "Percent": round(pct, 1)})
        except AccessDeniedError:
            log.warning("Access denied for secure scores in sub %s", sub_id)
        except Exception as exc:
            log.warning("Secure score failed for sub %s: %s", sub_id, exc)

    if scores:
        avg_pct = sum(s["Percent"] for s in scores) / len(scores)
        if avg_pct < 70:
            return [_risk_finding(
                category="defender",
                subcategory="low_secure_score",
                title=f"Secure Score {avg_pct:.0f}% (below 70% threshold)",
                description=f"Average secure score is {avg_pct:.1f}%, indicating significant security gaps.",
                severity="high" if avg_pct < 50 else "medium",
                affected_resources=scores,
                remediation={
                    "Description": "Address Defender recommendations to improve secure score.",
                    "PortalSteps": [
                        "Navigate to Microsoft Defender for Cloud > Secure Score",
                        "Review top recommendations by score impact",
                        "Prioritize quick wins and high-impact fixes",
                    ],
                },
            )]
    return []
