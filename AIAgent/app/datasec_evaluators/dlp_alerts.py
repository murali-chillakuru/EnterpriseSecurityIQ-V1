"""
Data Security — DLP Alert Effectiveness evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_dlp_alert_effectiveness(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess DLP alert volume and effectiveness from security alert metrics."""
    findings: list[dict] = []
    findings.extend(_check_dlp_alert_volume(evidence_index))
    return findings


def _check_dlp_alert_volume(idx: dict) -> list[dict]:
    """Analyze DLP alert metrics for anomalies or gaps."""
    dlp_metrics = idx.get("m365-dlp-alert-metrics", [])
    if not dlp_metrics:
        return []

    for ev in dlp_metrics:
        data = ev.get("Data", ev.get("data", {}))
        total_dlp = data.get("TotalDlpAlerts", 0)
        total_security = data.get("TotalSecurityAlerts", 0)
        severity_counts = data.get("SeverityCounts", {})

        # High volume of high-severity DLP alerts indicates active data leakage
        high_sev = severity_counts.get("high", 0) + severity_counts.get("critical", 0)
        if high_sev >= 5:
            return [_ds_finding(
                "m365_dlp", "high_severity_dlp_alerts",
                f"{high_sev} high/critical DLP alerts detected",
                f"There are {high_sev} high-severity DLP alerts, indicating "
                "active or recent attempts to share sensitive data. These require "
                "immediate investigation.",
                "high",
                [{"Type": "DLPAlert", **a} for a in data.get("RecentAlerts", [])[:5]],
                {"Description": "Investigate high-severity DLP alerts immediately.",
                 "PortalSteps": [
                     "Go to security.microsoft.com > Alerts",
                     "Filter by category: Data Loss Prevention",
                     "Review affected users, content, and sharing destinations",
                     "Take remediation action (block sharing, revoke access)",
                 ]},
            )]

        # No DLP alerts at all when policies exist may indicate poor coverage
        dlp_policies = idx.get("m365-dlp-policies", [])
        if dlp_policies and total_dlp == 0 and total_security > 0:
            return [_ds_finding(
                "m365_dlp", "no_dlp_alerts_with_policies",
                "DLP policies exist but no DLP alerts generated",
                "DLP policies are configured but have not generated any alerts. "
                "This may indicate policies are too permissive or not covering "
                "the right sensitive information types.",
                "low", [],
                {"Description": "Review DLP policy conditions and sensitive information types.",
                 "PortalSteps": [
                     "compliance.microsoft.com > Data loss prevention > Policies",
                     "Review each policy's conditions and SIT coverage",
                     "Check policy mode — ensure policies are enforcing, not just monitoring",
                 ]},
            )]
    return []


# ── Redis Security ────────────────────────────────────────────────────

