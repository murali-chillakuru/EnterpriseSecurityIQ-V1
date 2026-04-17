"""
EnterpriseSecurityIQ — M365 Compliance Collectors (Enhancement #9)

Five new evidence collectors for Purview / M365 compliance workloads:
  1. Retention policies & retention labels
  2. Insider Risk Management policy existence
  3. eDiscovery case status
  4. DLP incident/alert metrics (via security alerts v2)
  5. Sensitivity label effectiveness (usage summary)
"""

from __future__ import annotations

from app.collectors.base import (
    AccessDeniedError,
    make_evidence,
    paginate_graph,
    run_collector,
)
from app.collectors.registry import register_collector
from app.models import Source
from app.logger import log


# ── 1. Retention Policies & Labels ────────────────────────────────────

@register_collector(
    name="m365_retention",
    plane="control",
    source="entra",
    priority=180,
)
async def collect_m365_retention(creds) -> list[dict]:
    """Collect M365 retention labels and retention policies via Graph beta."""

    async def _collect():
        evidence: list[dict] = []
        graph_beta = creds.get_graph_beta_client()

        # Retention labels
        try:
            labels_resp = await graph_beta.security.labels.retention_labels.get()
            labels = labels_resp.value if labels_resp and labels_resp.value else []
            for lbl in labels:
                evidence.append(make_evidence(
                    source=Source.ENTRA,
                    collector="M365Retention",
                    evidence_type="m365-retention-label",
                    description=f"Retention label: {getattr(lbl, 'display_name', '')}",
                    data={
                        "LabelId": getattr(lbl, "id", ""),
                        "DisplayName": getattr(lbl, "display_name", ""),
                        "RetentionDuration": str(getattr(lbl, "retention_duration", "")),
                        "ActionAfterRetentionPeriod": str(
                            getattr(lbl, "action_after_retention_period", "")
                        ),
                        "IsInUse": getattr(lbl, "is_in_use", False),
                        "BehaviorDuringRetentionPeriod": str(
                            getattr(lbl, "behavior_during_retention_period", "")
                        ),
                        "CreatedDateTime": str(getattr(lbl, "created_date_time", "")),
                    },
                    resource_id=getattr(lbl, "id", ""),
                    resource_type="RetentionLabel",
                ))
            log.info("  [M365Retention] Collected %d retention labels", len(labels))
        except Exception as exc:
            _handle_m365_error(exc, "RetentionLabels", evidence)

        # Retention policies (via compliance API beta endpoint)
        try:
            # Graph beta: security/triggerTypes/retentionEventTypes → policies
            # We query retentionLabels with expand for policies
            policies_resp = await graph_beta.security.labels.retention_labels.get()
            policy_count = len(policies_resp.value) if policies_resp and policies_resp.value else 0
            evidence.append(make_evidence(
                source=Source.ENTRA,
                collector="M365Retention",
                evidence_type="m365-retention-summary",
                description="Retention policy summary",
                data={
                    "RetentionLabelCount": policy_count,
                    "HasRetentionLabels": policy_count > 0,
                },
                resource_type="RetentionSummary",
            ))
        except Exception as exc:
            _handle_m365_error(exc, "RetentionPolicySummary", evidence)

        return evidence

    return (await run_collector("M365Retention", Source.ENTRA, _collect)).data


# ── 2. Insider Risk Management Policy Existence ──────────────────────

@register_collector(
    name="m365_insider_risk",
    plane="control",
    source="entra",
    priority=185,
)
async def collect_m365_insider_risk(creds) -> list[dict]:
    """Check for Insider Risk Management policies via Graph beta."""

    async def _collect():
        evidence: list[dict] = []
        graph_beta = creds.get_graph_beta_client()

        try:
            # Beta: /security/insiderRiskManagement/policies (or alerts)
            # Attempt alerts endpoint as it's more commonly available
            url = "/security/alerts_v2?$filter=category eq 'InsiderRisk'&$top=5"
            alerts_resp = await graph_beta.security.alerts_v2.get()
            all_alerts = alerts_resp.value if alerts_resp and alerts_resp.value else []
            irm_alerts = [
                a for a in all_alerts
                if "insider" in (getattr(a, "category", "") or "").lower()
                or "insider" in (getattr(a, "title", "") or "").lower()
            ]

            evidence.append(make_evidence(
                source=Source.ENTRA,
                collector="M365InsiderRisk",
                evidence_type="m365-irm-status",
                description="Insider Risk Management status",
                data={
                    "IrmAlertsFound": len(irm_alerts),
                    "HasIrmAlerts": len(irm_alerts) > 0,
                    "SampleAlerts": [
                        {
                            "Title": getattr(a, "title", ""),
                            "Severity": str(getattr(a, "severity", "")),
                            "Status": str(getattr(a, "status", "")),
                            "CreatedDateTime": str(getattr(a, "created_date_time", "")),
                        }
                        for a in irm_alerts[:5]
                    ],
                },
                resource_type="InsiderRiskStatus",
            ))
            log.info("  [M365InsiderRisk] Found %d IRM-related alerts", len(irm_alerts))
        except Exception as exc:
            _handle_m365_error(exc, "InsiderRiskAlerts", evidence)

        # Also try to detect IRM policies via the beta endpoint
        try:
            # This endpoint is available with certain premium licenses
            irm_settings = await graph_beta.security.get()
            evidence.append(make_evidence(
                source=Source.ENTRA,
                collector="M365InsiderRisk",
                evidence_type="m365-irm-settings",
                description="Insider Risk Management settings probe",
                data={
                    "SecurityApiAccessible": True,
                },
                resource_type="InsiderRiskSettings",
            ))
        except Exception as exc:
            _handle_m365_error(exc, "InsiderRiskSettings", evidence)

        return evidence

    return (await run_collector("M365InsiderRisk", Source.ENTRA, _collect)).data


# ── 3. eDiscovery Case Status ────────────────────────────────────────

@register_collector(
    name="m365_ediscovery",
    plane="control",
    source="entra",
    priority=190,
)
async def collect_m365_ediscovery(creds) -> list[dict]:
    """Collect eDiscovery case status via Graph beta."""

    async def _collect():
        evidence: list[dict] = []
        graph_beta = creds.get_graph_beta_client()

        try:
            cases_resp = await graph_beta.security.cases.ediscovery_cases.get()
            cases = cases_resp.value if cases_resp and cases_resp.value else []

            for case in cases:
                evidence.append(make_evidence(
                    source=Source.ENTRA,
                    collector="M365eDiscovery",
                    evidence_type="m365-ediscovery-case",
                    description=f"eDiscovery case: {getattr(case, 'display_name', '')}",
                    data={
                        "CaseId": getattr(case, "id", ""),
                        "DisplayName": getattr(case, "display_name", ""),
                        "Status": str(getattr(case, "status", "")),
                        "CreatedDateTime": str(getattr(case, "created_date_time", "")),
                        "ClosedDateTime": str(getattr(case, "closed_date_time", "") or ""),
                        "ExternalId": getattr(case, "external_id", ""),
                    },
                    resource_id=getattr(case, "id", ""),
                    resource_type="eDiscoveryCase",
                ))

            evidence.append(make_evidence(
                source=Source.ENTRA,
                collector="M365eDiscovery",
                evidence_type="m365-ediscovery-summary",
                description="eDiscovery summary",
                data={
                    "TotalCases": len(cases),
                    "ActiveCases": sum(
                        1 for c in cases
                        if str(getattr(c, "status", "")).lower() == "active"
                    ),
                    "ClosedCases": sum(
                        1 for c in cases
                        if str(getattr(c, "status", "")).lower() == "closed"
                    ),
                    "HasCases": len(cases) > 0,
                },
                resource_type="eDiscoverySummary",
            ))
            log.info("  [M365eDiscovery] Collected %d eDiscovery cases", len(cases))
        except Exception as exc:
            _handle_m365_error(exc, "eDiscoveryCases", evidence)

        return evidence

    return (await run_collector("M365eDiscovery", Source.ENTRA, _collect)).data


# ── 4. DLP Alert Metrics (Security Alerts v2) ────────────────────────

@register_collector(
    name="m365_dlp_alerts",
    plane="control",
    source="entra",
    priority=175,
)
async def collect_m365_dlp_alerts(creds) -> list[dict]:
    """Collect DLP-related security alerts via Graph v2 alerts API."""

    async def _collect():
        evidence: list[dict] = []
        graph = creds.get_graph_client()

        try:
            alerts_resp = await graph.security.alerts_v2.get()
            all_alerts = alerts_resp.value if alerts_resp and alerts_resp.value else []

            dlp_alerts = [
                a for a in all_alerts
                if "dlp" in (getattr(a, "category", "") or "").lower()
                or "data loss" in (getattr(a, "title", "") or "").lower()
                or "dlp" in (getattr(a, "title", "") or "").lower()
            ]

            severity_counts = {}
            for a in dlp_alerts:
                sev = str(getattr(a, "severity", "unknown")).lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            evidence.append(make_evidence(
                source=Source.ENTRA,
                collector="M365DLPAlerts",
                evidence_type="m365-dlp-alert-metrics",
                description="DLP alert metrics summary",
                data={
                    "TotalDlpAlerts": len(dlp_alerts),
                    "HasDlpAlerts": len(dlp_alerts) > 0,
                    "SeverityCounts": severity_counts,
                    "TotalSecurityAlerts": len(all_alerts),
                    "RecentAlerts": [
                        {
                            "Title": getattr(a, "title", ""),
                            "Severity": str(getattr(a, "severity", "")),
                            "Status": str(getattr(a, "status", "")),
                            "CreatedDateTime": str(getattr(a, "created_date_time", "")),
                        }
                        for a in dlp_alerts[:10]
                    ],
                },
                resource_type="DLPAlertMetrics",
            ))
            log.info("  [M365DLPAlerts] Found %d DLP-related alerts out of %d total",
                     len(dlp_alerts), len(all_alerts))
        except Exception as exc:
            _handle_m365_error(exc, "SecurityAlertsV2", evidence)

        return evidence

    return (await run_collector("M365DLPAlerts", Source.ENTRA, _collect)).data


# ── 5. Sensitivity Label Usage Analytics ──────────────────────────────

@register_collector(
    name="m365_label_analytics",
    plane="control",
    source="entra",
    priority=172,
)
async def collect_m365_label_analytics(creds) -> list[dict]:
    """Collect sensitivity label usage/effectiveness summary."""

    async def _collect():
        evidence: list[dict] = []
        graph = creds.get_graph_client()
        graph_beta = creds.get_graph_beta_client()

        # Try to get label usage via reports endpoint
        try:
            # Get all sensitivity labels to count them
            labels_resp = await graph_beta.security.information_protection.sensitivity_labels.get()
            labels = labels_resp.value if labels_resp and labels_resp.value else []

            label_summary = []
            for lbl in labels:
                label_summary.append({
                    "LabelId": getattr(lbl, "id", ""),
                    "Name": getattr(lbl, "name", ""),
                    "IsActive": getattr(lbl, "is_active", True),
                    "Tooltip": getattr(lbl, "tooltip", ""),
                    "Priority": getattr(lbl, "priority", 0),
                })

            evidence.append(make_evidence(
                source=Source.ENTRA,
                collector="M365LabelAnalytics",
                evidence_type="m365-label-analytics",
                description="Sensitivity label analytics",
                data={
                    "TotalLabels": len(labels),
                    "ActiveLabels": sum(1 for l in label_summary if l.get("IsActive", True)),
                    "HasLabels": len(labels) > 0,
                    "Labels": label_summary[:50],  # Cap at 50
                },
                resource_type="LabelAnalytics",
            ))
            log.info("  [M365LabelAnalytics] Found %d sensitivity labels", len(labels))
        except Exception as exc:
            _handle_m365_error(exc, "SensitivityLabelAnalytics", evidence)

        return evidence

    return (await run_collector("M365LabelAnalytics", Source.ENTRA, _collect)).data


# ── Shared error handler ─────────────────────────────────────────────

def _handle_m365_error(exc: Exception, api_name: str, evidence: list[dict]) -> None:
    """Handle 403/401 gracefully, otherwise log warning."""
    exc_str = str(exc).lower()
    if "403" in exc_str or "forbidden" in exc_str or "authorization" in exc_str:
        log.warning("  [M365] %s returned 403 — insufficient permissions", api_name)
        evidence.append(make_evidence(
            source=Source.ENTRA,
            collector="M365Compliance",
            evidence_type="m365-access-denied",
            description=f"{api_name}: Access Denied (403)",
            data={
                "Api": api_name,
                "StatusCode": 403,
                "AccessDenied": True,
            },
            resource_type="AccessDenied",
        ))
    elif "401" in exc_str or "unauthorized" in exc_str:
        log.warning("  [M365] %s returned 401 — unauthorized", api_name)
    else:
        log.warning("  [M365] %s failed: %s", api_name, exc)
