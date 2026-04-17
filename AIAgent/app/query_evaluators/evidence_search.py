"""Full-text evidence search utilities."""

from __future__ import annotations
from typing import Any

def search_evidence(
    evidence: list[dict],
    query: str,
    evidence_types: list[str] | None = None,
    severity_filter: str | None = None,
    max_results: int = 100,
) -> list[dict]:
    """Full-text search across all collected evidence records.

    Searches through EvidenceType, Description, Collector, ResourceId,
    ResourceType, and all Data field values (recursively).

    Args:
        evidence:       Full evidence list from assessment.
        query:          Free-text search string (case-insensitive).
        evidence_types: Optional filter to specific evidence types.
        severity_filter: Not applicable to evidence directly, but passed through.
        max_results:    Maximum number of results to return.

    Returns:
        Matching evidence records sorted by relevance (match count).
    """
    q = query.lower().strip()
    if not q:
        return []

    # Split query into terms for multi-word matching
    terms = q.split()
    matched: list[tuple[int, dict]] = []

    for record in evidence:
        # Apply evidence type filter
        if evidence_types:
            etype = record.get("EvidenceType", "")
            if etype not in evidence_types:
                continue

        # Build searchable text from all record fields
        searchable_parts = [
            str(record.get("EvidenceType", "")),
            str(record.get("Description", "")),
            str(record.get("Collector", "")),
            str(record.get("ResourceId", "")),
            str(record.get("ResourceType", "")),
            str(record.get("Source", "")),
        ]

        # Recursively extract Data field values
        data = record.get("Data", {})
        if isinstance(data, dict):
            searchable_parts.extend(_flatten_dict_values(data))

        searchable = " ".join(searchable_parts).lower()

        # Count how many query terms match
        match_count = sum(1 for term in terms if term in searchable)
        if match_count > 0:
            matched.append((match_count, record))

    # Sort by match count (descending) for relevance
    matched.sort(key=lambda x: x[0], reverse=True)
    return [r for _, r in matched[:max_results]]


def search_evidence_advanced(
    evidence: list[dict],
    filters: dict[str, Any],
    max_results: int = 100,
) -> list[dict]:
    """Advanced evidence search with structured filters.

    Args:
        evidence: Full evidence list.
        filters: Dict of filter criteria:
            - query: str — free-text search
            - evidence_type: str | list[str] — filter by type
            - resource_type: str — filter by resource type
            - subscription_id: str — filter by subscription
            - location: str — filter by location
            - collector: str — filter by collector name
            - has_field: str — records that have a specific Data field
            - field_value: dict — {field_name: expected_value} exact match
        max_results: Maximum results.

    Returns:
        Matching evidence records.
    """
    results = list(evidence)

    # Apply structured filters first (narrowing)
    etype = filters.get("evidence_type")
    if etype:
        if isinstance(etype, str):
            etype = [etype]
        results = [r for r in results if r.get("EvidenceType", "") in etype]

    resource_type = filters.get("resource_type")
    if resource_type:
        results = [r for r in results if resource_type.lower() in (r.get("ResourceType", "") or "").lower()]

    sub_id = filters.get("subscription_id")
    if sub_id:
        results = [r for r in results if sub_id in str(r.get("Data", {}).get("SubscriptionId", ""))]

    location = filters.get("location")
    if location:
        loc_lower = location.lower()
        results = [r for r in results if loc_lower in (r.get("Data", {}).get("Location", "") or "").lower()]

    collector = filters.get("collector")
    if collector:
        results = [r for r in results if collector.lower() in (r.get("Collector", "") or "").lower()]

    has_field = filters.get("has_field")
    if has_field:
        results = [r for r in results if has_field in (r.get("Data", {}) or {})]

    field_value = filters.get("field_value")
    if field_value and isinstance(field_value, dict):
        for fname, fval in field_value.items():
            results = [r for r in results if r.get("Data", {}).get(fname) == fval]

    # Apply free-text search last
    query = filters.get("query")
    if query:
        results = search_evidence(results, query, max_results=max_results)

    return results[:max_results]


def _flatten_dict_values(d: dict, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a nested dict."""
    if depth > 5:
        return []
    parts: list[str] = []
    for v in d.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (int, float, bool)):
            parts.append(str(v))
        elif isinstance(v, dict):
            parts.extend(_flatten_dict_values(v, depth + 1))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.extend(_flatten_dict_values(item, depth + 1))
    return parts
