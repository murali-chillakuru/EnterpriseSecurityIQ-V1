"""
Shared risk-finding constructor and constants for all risk evaluators.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


# ── Severity weight map for risk scoring ────────────────────────────────
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 1.0,
}


def risk_finding(
    category: str,
    subcategory: str,
    title: str,
    description: str,
    severity: str,
    affected_resources: list[dict] | None = None,
    remediation: dict | None = None,
    evidence: list[dict] | None = None,
) -> dict:
    """Create a standardised risk-finding dict (PascalCase keys)."""
    return {
        "RiskFindingId": str(uuid.uuid4()),
        "Category": category,
        "Subcategory": subcategory,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "AffectedResources": affected_resources or [],
        "AffectedCount": len(affected_resources) if affected_resources else 0,
        "Remediation": remediation or {},
        "Evidence": evidence or [],
        "DetectedAt": datetime.now(timezone.utc).isoformat(),
    }
