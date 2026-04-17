"""
Risk evaluator — Insider Risk Management signals.

Checks: IRM policy existence, active IRM alerts.
"""
from __future__ import annotations

from app.risk_evaluators.finding import risk_finding as _risk_finding


def analyze_insider_risk(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Analyze Insider Risk Management posture from M365 compliance evidence."""
    findings: list[dict] = []
    findings.extend(_check_irm_policy_existence(evidence_index))
    findings.extend(_check_irm_active_alerts(evidence_index))
    return findings


def _check_irm_policy_existence(evidence_index: dict) -> list[dict]:
    """Flag if no Insider Risk Management policies are detected."""
    irm_status = evidence_index.get("m365-irm-status", [])
    irm_settings = evidence_index.get("m365-irm-settings", [])

    if not irm_status and not irm_settings:
        has_m365 = any(
            k.startswith("m365-") or k.startswith("entra-")
            for k in evidence_index
        )
        if has_m365:
            return [_risk_finding(
                category="insider_risk",
                subcategory="irm_not_assessed",
                title="Insider Risk Management status could not be assessed",
                description=(
                    "No IRM evidence was collected — the Insider Risk Management API "
                    "may require additional permissions (InsiderRiskManagement.Read.All) "
                    "or the feature may not be licensed."
                ),
                severity="medium",
                remediation={
                    "Description": "Enable Insider Risk Management in Microsoft Purview.",
                    "PortalSteps": [
                        "Go to compliance.microsoft.com > Insider Risk Management",
                        "Create a policy (e.g., 'Data theft by departing users')",
                        "Configure indicators and thresholds",
                    ],
                },
            )]
        return []

    for ev in irm_status:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasIrmAlerts"):
            return []  # IRM is active

    return [_risk_finding(
        category="insider_risk",
        subcategory="no_irm_policies",
        title="No Insider Risk Management policies detected",
        description=(
            "No IRM alerts found, indicating policies may not be configured. "
            "Insider Risk Management helps detect risky user activities such as "
            "data exfiltration, IP theft, and policy violations."
        ),
        severity="medium",
        remediation={
            "Description": "Configure Insider Risk Management policies in Purview.",
            "PortalSteps": [
                "Go to compliance.microsoft.com > Insider Risk Management > Policies",
                "Create at least one policy: 'Data theft by departing users' or 'General data leaks'",
                "Enable HR connector for departure signals (recommended)",
                "Monitor the Alerts dashboard for triggered indicators",
            ],
        },
    )]


def _check_irm_active_alerts(evidence_index: dict) -> list[dict]:
    """Flag active insider risk alerts that need investigation."""
    irm_status = evidence_index.get("m365-irm-status", [])
    for ev in irm_status:
        data = ev.get("Data", ev.get("data", {}))
        alert_count = data.get("IrmAlertsFound", 0)
        if alert_count > 0:
            sample = data.get("SampleAlerts", [])
            affected = [
                {
                    "Type": "InsiderRiskAlert",
                    "Title": a.get("Title", ""),
                    "Severity": a.get("Severity", ""),
                    "Status": a.get("Status", ""),
                }
                for a in sample
            ]
            return [_risk_finding(
                category="insider_risk",
                subcategory="active_irm_alerts",
                title=f"{alert_count} insider risk alerts require investigation",
                description=(
                    f"Insider Risk Management has flagged {alert_count} alerts. "
                    "Unresolved insider risk alerts may indicate active data leakage or policy violations."
                ),
                severity="high" if alert_count >= 5 else "medium",
                affected_resources=affected,
                remediation={
                    "Description": "Review and triage insider risk alerts in Microsoft Purview.",
                    "PortalSteps": [
                        "Go to compliance.microsoft.com > Insider Risk Management > Alerts",
                        "Review alert details and user activity timeline",
                        "Escalate high-severity alerts or create cases for investigation",
                    ],
                },
            )]
    return []
