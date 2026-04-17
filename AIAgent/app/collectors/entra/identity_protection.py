"""
Entra Identity Protection Collector
Risky users, risky service principals, risk detections.
"""

from __future__ import annotations
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence, AccessDeniedError
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="identity_protection", plane="control", source="entra", priority=90)
async def collect_entra_identity_protection(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()
        graph_beta = creds.get_graph_beta_client()

        # Risky Users
        try:
            risky_users = await paginate_graph(graph.identity_protection.risky_users)
            for user in risky_users:
                risk_level = str(getattr(user, "risk_level", "none"))
                risk_state = str(getattr(user, "risk_state", "none"))
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraIdentityProtection",
                    evidence_type="entra-risky-user",
                    description=f"Risky user: {getattr(user, 'user_display_name', '')}",
                    data={
                        "UserId": getattr(user, "id", ""),
                        "UserDisplayName": getattr(user, "user_display_name", ""),
                        "UserPrincipalName": getattr(user, "user_principal_name", ""),
                        "RiskLevel": risk_level,
                        "RiskState": risk_state,
                        "RiskLastUpdatedDateTime": str(getattr(user, "risk_last_updated_date_time", "")),
                        "IsHighRisk": "high" in risk_level.lower(),
                    },
                    resource_id=getattr(user, "id", ""), resource_type="RiskyUser",
                ))
            log.info("  [EntraIdentityProtection] %d risky users", len(risky_users))
        except AccessDeniedError as ade:
            log.warning("  [EntraIdentityProtection] Risky users access denied (HTTP %d) — skipping", ade.status)
        except Exception as exc:
            log.warning("  [EntraIdentityProtection] Risky users: %s", exc)

        # Risky Service Principals (beta-only endpoint, requires Workload Identity Premium)
        try:
            risky_sps = await paginate_graph(
                graph_beta.identity_protection.risky_service_principals
            )
            for sp in risky_sps:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraIdentityProtection",
                    evidence_type="entra-risky-service-principal",
                    description=f"Risky SP: {getattr(sp, 'display_name', '')}",
                    data={
                        "ServicePrincipalId": getattr(sp, "id", ""),
                        "DisplayName": getattr(sp, "display_name", ""),
                        "AppId": getattr(sp, "app_id", ""),
                        "RiskLevel": str(getattr(sp, "risk_level", "none")),
                        "RiskState": str(getattr(sp, "risk_state", "none")),
                    },
                    resource_type="RiskyServicePrincipal",
                ))
        except AccessDeniedError as ade:
            log.warning("  [EntraIdentityProtection] Risky SPs access denied (HTTP %d) — skipping", ade.status)
        except Exception as exc:
            log.warning("  [EntraIdentityProtection] Risky SPs: %s", exc)

        # Risk Detections (last 30 days)
        try:
            detections = await paginate_graph(graph.identity_protection.risk_detections)
            high_risk = 0
            medium_risk = 0
            for det in detections:
                level = str(getattr(det, "risk_level", ""))
                if "high" in level.lower():
                    high_risk += 1
                elif "medium" in level.lower():
                    medium_risk += 1

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraIdentityProtection",
                    evidence_type="entra-risk-detection",
                    description=f"Risk: {getattr(det, 'risk_event_type', '')}",
                    data={
                        "Id": getattr(det, "id", ""),
                        "RiskEventType": getattr(det, "risk_event_type", ""),
                        "RiskLevel": level,
                        "RiskState": str(getattr(det, "risk_state", "")),
                        "DetectedDateTime": str(getattr(det, "detected_date_time", "")),
                        "UserId": getattr(det, "user_id", ""),
                        "UserDisplayName": getattr(det, "user_display_name", ""),
                        "IpAddress": getattr(det, "ip_address", ""),
                    },
                    resource_type="RiskDetection",
                ))

            evidence.append(make_evidence(
                source=Source.ENTRA, collector="EntraIdentityProtection",
                evidence_type="entra-risk-summary",
                description="Risk detection summary",
                data={
                    "TotalDetections": len(detections),
                    "HighRiskDetections": high_risk,
                    "MediumRiskDetections": medium_risk,
                },
            ))
            log.info("  [EntraIdentityProtection] %d risk detections", len(detections))
        except AccessDeniedError as ade:
            log.warning("  [EntraIdentityProtection] Risk detections access denied (HTTP %d) — skipping", ade.status)
        except Exception as exc:
            log.warning("  [EntraIdentityProtection] Risk detections: %s", exc)

        return evidence

    return (await run_collector("EntraIdentityProtection", Source.ENTRA, _collect)).data
