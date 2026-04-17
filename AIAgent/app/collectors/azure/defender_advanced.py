"""
Azure Defender Advanced Collector
Security recommendations, secure score, assessments, sub-assessments,
compliance results, and JIT access policies.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.security.aio import SecurityCenter
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="defender_advanced", plane="control", source="azure", priority=91)
async def collect_azure_defender_advanced(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                client = SecurityCenter(creds.credential, sub_id, asc_location="centralus")

                # --- Secure Score ---
                try:
                    scores = await paginate_arm(client.secure_scores.list())
                    for score in scores:
                        props = score.properties if hasattr(score, "properties") else score
                        current = getattr(props, "score", None) or getattr(score, "score", None)
                        current_val = getattr(current, "current", 0) if current else 0
                        max_val = getattr(current, "max", 0) if current else 0
                        percentage = getattr(props, "percentage", 0)

                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDefenderAdvanced",
                            evidence_type="azure-secure-score",
                            description=f"Secure Score: {score.name}",
                            data={
                                "ScoreId": score.id,
                                "Name": score.name,
                                "CurrentScore": current_val,
                                "MaxScore": max_val,
                                "Percentage": percentage,
                                "Weight": getattr(props, "weight", 0),
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=score.id or "", resource_type="SecureScore",
                        ))
                except Exception as exc:
                    log.warning("  [DefenderAdvanced] %s Secure Score failed: %s", sub_name, exc)

                # --- Security Recommendations (Assessments) ---
                try:
                    assessments = await paginate_arm(client.assessments.list(
                        scope=f"/subscriptions/{sub_id}"
                    ))
                    for asmt in assessments:
                        status = getattr(asmt, "status", None) or type("S", (), {"code": "Unknown"})()
                        resource_details = getattr(asmt, "resource_details", None)
                        metadata = getattr(asmt, "metadata", None)

                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDefenderAdvanced",
                            evidence_type="azure-security-assessment",
                            description=f"Assessment: {asmt.display_name or asmt.name}",
                            data={
                                "AssessmentId": asmt.id,
                                "Name": asmt.name,
                                "DisplayName": getattr(asmt, "display_name", ""),
                                "StatusCode": _v(getattr(status, "code", None)),
                                "StatusCause": getattr(status, "cause", ""),
                                "StatusDescription": getattr(status, "description", ""),
                                "Severity": _v(getattr(metadata, "severity", None)) if metadata else "",
                                "Category": _v(getattr(metadata, "category", None)) if metadata else "",
                                "ResourceSource": _v(getattr(resource_details, "source", None)) if resource_details else "",
                                "AzureResourceId": getattr(resource_details, "id", "") if resource_details else "",
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=asmt.id or "", resource_type="SecurityAssessment",
                        ))
                except Exception as exc:
                    log.warning("  [DefenderAdvanced] %s Assessments failed: %s", sub_name, exc)

                # --- Regulatory Compliance Standards ---
                try:
                    standards = await paginate_arm(
                        client.regulatory_compliance_standards.list()
                    )
                    for std in standards:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDefenderAdvanced",
                            evidence_type="azure-regulatory-compliance",
                            description=f"Compliance Standard: {std.name}",
                            data={
                                "StandardId": std.id,
                                "Name": std.name,
                                "State": _v(getattr(std, "state", None)),
                                "PassedControls": getattr(std, "passed_controls", 0),
                                "FailedControls": getattr(std, "failed_controls", 0),
                                "SkippedControls": getattr(std, "skipped_controls", 0),
                                "UnsupportedControls": getattr(std, "unsupported_controls", 0),
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=std.id or "", resource_type="RegulatoryComplianceStandard",
                        ))
                except Exception as exc:
                    log.warning("  [DefenderAdvanced] %s Regulatory Compliance failed: %s", sub_name, exc)

                # --- JIT Network Access Policies ---
                try:
                    jit_policies = await paginate_arm(
                        client.jit_network_access_policies.list()
                    )
                    for jit in jit_policies:
                        vms = getattr(jit, "virtual_machines", []) or []
                        requests_list = getattr(jit, "requests", []) or []
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDefenderAdvanced",
                            evidence_type="azure-jit-policy",
                            description=f"JIT Policy: {jit.name}",
                            data={
                                "PolicyId": jit.id,
                                "Name": jit.name,
                                "Location": getattr(jit, "location", ""),
                                "Kind": getattr(jit, "kind", ""),
                                "ProvisioningState": getattr(jit, "provisioning_state", ""),
                                "VirtualMachineCount": len(vms),
                                "RequestCount": len(requests_list),
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=jit.id or "", resource_type="JitPolicy",
                        ))
                except Exception as exc:
                    log.warning("  [DefenderAdvanced] %s JIT Policies failed: %s", sub_name, exc)

                # --- Alerts ---
                try:
                    alerts = await paginate_arm(client.alerts.list())
                    for alert in alerts:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDefenderAdvanced",
                            evidence_type="azure-security-alert",
                            description=f"Alert: {alert.alert_display_name or alert.name}",
                            data={
                                "AlertId": alert.id,
                                "Name": alert.name,
                                "DisplayName": getattr(alert, "alert_display_name", ""),
                                "AlertType": getattr(alert, "alert_type", ""),
                                "Severity": _v(getattr(alert, "severity", None)),
                                "Status": _v(getattr(alert, "status", None)),
                                "Intent": _v(getattr(alert, "intent", None)),
                                "CompromisedEntity": getattr(alert, "compromised_entity", ""),
                                "StartTimeUtc": str(getattr(alert, "start_time_utc", "")),
                                "EndTimeUtc": str(getattr(alert, "end_time_utc", "")),
                                "IsIncident": getattr(alert, "is_incident", False),
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=alert.id or "", resource_type="SecurityAlert",
                        ))
                except Exception as exc:
                    log.warning("  [DefenderAdvanced] %s Alerts failed: %s", sub_name, exc)

                await client.close()
            except Exception as exc:
                log.warning("  [DefenderAdvanced] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureDefenderAdvanced", Source.AZURE, _collect)).data
