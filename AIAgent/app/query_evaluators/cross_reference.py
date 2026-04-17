"""Cross-reference findings search utility."""

from __future__ import annotations

def cross_reference_findings(
    findings: list[dict],
    query: str,
) -> list[dict]:
    """Search assessment findings by resource, control ID, domain, severity, or keyword.

    Returns matching findings sorted by severity.
    """
    q = query.lower()
    matched = []

    for f in findings:
        searchable = " ".join([
            str(f.get("ControlId", "")),
            str(f.get("ControlTitle", "")),
            str(f.get("Domain", "")),
            str(f.get("Severity", "")),
            str(f.get("Status", "")),
            str(f.get("Description", "")),
            str(f.get("Recommendation", "")),
            str(f.get("ResourceId", "")),
            str(f.get("ResourceType", "")),
        ]).lower()

        if q in searchable:
            matched.append(f)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    matched.sort(key=lambda x: severity_order.get(x.get("Severity", "").lower(), 5))
    return matched


# ---------------------------------------------------------------------------
# Keyword maps — now live in cloud_explorer.keyword_map.
# Re-exported here for backward compat (dispatcher imports).
# ---------------------------------------------------------------------------
from app.cloud_explorer.keyword_map import NL_ARG_MAP as _NL_ARG_MAP  # noqa: F401
from app.cloud_explorer.keyword_map import NL_ENTRA_MAP as _NL_ENTRA_MAP  # noqa: F401

