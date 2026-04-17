"""Shared finding constructor and constants for Copilot Readiness evaluators."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

# Stable UUID namespace for deterministic finding IDs
_CR_FINDING_NS = uuid.UUID("b2e4a6c8-d0f2-4a1b-8c3e-5f7a9b1d3e5c")

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 1.0,
}


def _cr_finding(
    category: str,
    subcategory: str,
    title: str,
    description: str,
    severity: str,
    affected_resources: list[dict] | None = None,
    remediation: dict | None = None,
    compliance_status: str = "gap",
) -> dict:
    """Create a standardised Copilot readiness finding dict.

    The finding ID is deterministic: derived from category, subcategory,
    and sorted affected resource IDs so identical inputs always produce
    the same ID.
    """
    resources = affected_resources or []
    # Sort AffectedResources by ResourceId for deterministic output
    resources = sorted(
        resources,
        key=lambda r: r.get("ResourceId", r.get("Name", "")),
    )
    # Build a stable fingerprint from category + subcategory + sorted resource IDs
    resource_ids = [r.get("ResourceId", r.get("Name", "")) for r in resources]
    fingerprint = f"{category}|{subcategory}|{'|'.join(resource_ids)}"
    finding_id = str(uuid.uuid5(_CR_FINDING_NS, fingerprint))

    return {
        "CopilotReadinessFindingId": finding_id,
        "Category": category,
        "Subcategory": subcategory,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "ComplianceStatus": compliance_status,  # "compliant", "gap", "partial"
        "AffectedResources": resources,
        "AffectedCount": len(resources),
        "Remediation": remediation or {},
        "DetectedAt": datetime.now(timezone.utc).isoformat(),
    }

