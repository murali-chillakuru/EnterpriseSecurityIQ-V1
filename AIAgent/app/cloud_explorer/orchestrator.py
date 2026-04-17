"""Cloud Explorer orchestrator — routes composite query names to functions."""

from __future__ import annotations
from typing import Any

from app.auth import ComplianceCredentials
from app.logger import log
from .composite_queries import hierarchy_tree, security_snapshot, resource_drill_down


# ---------------------------------------------------------------------------
# Composite query registry
# ---------------------------------------------------------------------------

_COMPOSITE_DISPATCH = {
    "hierarchy_tree": hierarchy_tree,
    "security_snapshot": security_snapshot,
    "resource_drill_down": resource_drill_down,
}

# Exported set of names for validation in the dispatcher
COMPOSITE_NAMES = set(_COMPOSITE_DISPATCH.keys())


async def run_composite_query(
    creds: ComplianceCredentials,
    query_name: str,
    top: int = 200,
) -> dict[str, Any]:
    """Execute a composite query by name.

    Returns the same ``{source, query_used, results, count}`` dict shape
    as ``dispatch_natural_language``.
    """
    func = _COMPOSITE_DISPATCH.get(query_name)
    if not func:
        return {
            "source": "none",
            "query_used": "",
            "results": [],
            "count": 0,
            "message": f"Unknown composite query: {query_name}. "
                       f"Available: {', '.join(sorted(COMPOSITE_NAMES))}",
        }

    log.info("[cloud_explorer] Running composite query: %s", query_name)
    return await func(creds, top=top)
