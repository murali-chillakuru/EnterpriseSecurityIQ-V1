"""Shared finding constructor and constants for AI Agent Security evaluators."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

_SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 1.0,
}


def _as_finding(
    category: str,
    subcategory: str,
    title: str,
    description: str,
    severity: str,
    platform: str = "cross-cutting",
    affected_resources: list[dict] | None = None,
    remediation: dict | None = None,
    compliance_status: str = "gap",
) -> dict:
    """Create a standardised AI agent security finding dict."""
    return {
        "AgentSecurityFindingId": str(uuid.uuid4()),
        "Category": category,
        "Subcategory": subcategory,
        "Platform": platform,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "ComplianceStatus": compliance_status,
        "AffectedResources": affected_resources or [],
        "AffectedCount": len(affected_resources) if affected_resources else 0,
        "Remediation": remediation or {},
        "DetectedAt": datetime.now(timezone.utc).isoformat(),
    }

