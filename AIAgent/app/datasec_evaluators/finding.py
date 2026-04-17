"""
Data Security — Finding helper & constants.

Shared by all datasec_evaluators modules.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

# ── Severity weights (shared with risk_engine) ─────────────────────────
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 1.0,
}

# Stable UUID namespace for deterministic finding IDs
DS_FINDING_NS = uuid.UUID("7a3f1e2b-9c5d-4f8a-b6e1-2d3c4a5b6e7f")


def ds_finding(
    category: str,
    subcategory: str,
    title: str,
    description: str,
    severity: str,
    affected_resources: list[dict] | None = None,
    remediation: dict | None = None,
    *,
    assessed_at: str | None = None,
) -> dict:
    """Create a standardised data-security finding dict.

    The finding ID is deterministic: derived from category, subcategory,
    and sorted affected resource IDs so identical inputs always produce
    the same ID.
    """
    resources = affected_resources or []
    resource_ids = sorted(
        r.get("ResourceId", r.get("Name", ""))
        for r in resources
    )
    fingerprint = f"{category}|{subcategory}|{'|'.join(resource_ids)}"
    finding_id = str(uuid.uuid5(DS_FINDING_NS, fingerprint))

    return {
        "DataSecurityFindingId": finding_id,
        "Category": category,
        "Subcategory": subcategory,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "AffectedResources": resources,
        "AffectedCount": len(resources),
        "Remediation": remediation or {},
        "DetectedAt": assessed_at or datetime.now(timezone.utc).isoformat(),
    }
