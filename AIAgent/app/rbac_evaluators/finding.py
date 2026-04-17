"""
RBAC — Finding helper & constants.

Shared by all rbac_evaluators modules.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

# ── Severity weights (shared with scoring) ──────────────────────────────
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 1.0,
}

# Stable UUID namespace for deterministic finding IDs
RBAC_FINDING_NS = uuid.UUID("b4e2a1c7-6d3f-4a89-9e5b-1f2c3d4e5a6b")


def rbac_finding(
    category: str,
    subcategory: str,
    title: str,
    description: str,
    severity: str,
    affected_resources: list[dict] | None = None,
    affected_count: int = 0,
    remediation: dict | None = None,
    *,
    assessed_at: str | None = None,
    **extra,
) -> dict:
    """Create a standardised RBAC finding dict.

    The finding ID is deterministic: derived from category, subcategory,
    and sorted affected resource IDs so identical inputs always produce
    the same ID.
    """
    resources = affected_resources or []
    resource_ids = sorted(
        r.get("PrincipalId", r.get("Scope", ""))
        for r in resources
    )
    fingerprint = f"{category}|{subcategory}|{'|'.join(resource_ids)}"
    finding_id = str(uuid.uuid5(RBAC_FINDING_NS, fingerprint))

    return {
        "RbacFindingId": finding_id,
        "Category": category,
        "Subcategory": subcategory,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "AffectedResources": resources,
        "AffectedCount": affected_count or len(resources),
        "Remediation": remediation or {},
        "DetectedAt": assessed_at or datetime.now(timezone.utc).isoformat(),
        **extra,
    }
