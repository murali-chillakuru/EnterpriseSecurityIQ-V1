"""
Data Security — Tag-based data classification (legacy).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_data_classification(evidence_index: dict[str, list[dict]]) -> list[dict]:  # noqa: ARG001
    """Legacy entry-point — classification is now folded into data_access_controls."""
    return []


def _check_sensitive_data_tags(idx: dict) -> list[dict]:
    """Flag resources tagged with sensitivity indicators but lacking extra protection."""
    resources = idx.get("azure-resource", [])
    sensitive_keywords = {"confidential", "pii", "phi", "pci", "secret", "restricted", "sensitive"}
    flagged: list[dict] = []

    for ev in resources:
        data = ev.get("Data", ev.get("data", {}))
        tags = data.get("Tags", data.get("tags")) or {}
        for tag_key, tag_val in tags.items():
            combined = f"{tag_key} {tag_val}".lower()
            if any(kw in combined for kw in sensitive_keywords):
                flagged.append({
                    "Type": data.get("ResourceType", data.get("type", "Unknown")),
                    "Name": data.get("Name", data.get("name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "SensitiveTag": f"{tag_key}={tag_val}",
                })
                break

    if flagged:
        return [_ds_finding(
            "data_access", "sensitive_tagged_resources",
            f"{len(flagged)} resources tagged as sensitive",
            "Resources tagged with sensitivity indicators should have enhanced protection "
            "(encryption, network isolation, access reviews).",
            "informational", flagged,
            {"Description": "Review each tagged resource to ensure appropriate controls are in place.",
             "PortalSteps": [
                 "Cross-reference with classification policy",
                 "Verify encryption, network isolation, and RBAC for each resource",
             ]},
        )]
    return []


