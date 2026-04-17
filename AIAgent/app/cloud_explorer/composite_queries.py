"""Composite queries — multi-step orchestrations for Cloud Explorer.

Each function takes ComplianceCredentials and returns a structured result
dict with ``{source, query_used, results, count}``.
"""

from __future__ import annotations
from typing import Any

from app.auth import ComplianceCredentials
from app.logger import log
from app.query_evaluators.arg_queries import query_resource_graph
from app.query_evaluators.entra_dispatcher import _run_entra_query
from .arg_templates import ARG_TEMPLATES


# ---------------------------------------------------------------------------
# hierarchy_tree  — MGs → Subscriptions → RGs → Resources
# ---------------------------------------------------------------------------

async def hierarchy_tree(
    creds: ComplianceCredentials, top: int = 200,
) -> dict[str, Any]:
    """Build a full management-group → subscription → RG → resource tree.

    Uses MG-scoped queries for management groups, then subscription-scoped
    queries for the rest.  Returns a nested tree structure.
    """
    # 1. Management groups (MG-scoped query using tenant root group)
    mg_rows: list[dict] = []
    tenant_id = creds.tenant_id
    if tenant_id:
        try:
            mg_rows = await query_resource_graph(
                creds,
                ARG_TEMPLATES["management_groups"],
                management_group_ids=[tenant_id],
                top=top,
            )
            for r in mg_rows:
                r["_level"] = "management_group"
        except Exception as exc:
            log.warning("[hierarchy_tree] MG query failed: %s", exc)
            mg_rows = [{"_level": "management_group", "_error": str(exc)}]
    else:
        log.warning("[hierarchy_tree] No tenant_id — skipping MG query")

    # 2. Subscriptions
    try:
        sub_rows = await query_resource_graph(
            creds, ARG_TEMPLATES["subscriptions"], top=top,
        )
        for r in sub_rows:
            r["_level"] = "subscription"
    except Exception as exc:
        log.warning("[hierarchy_tree] Subscriptions query failed: %s", exc)
        sub_rows = [{"_level": "subscription", "_error": str(exc)}]

    # 3. Resource groups
    try:
        rg_rows = await query_resource_graph(
            creds, ARG_TEMPLATES["resource_groups"], top=1000,
        )
        for r in rg_rows:
            r["_level"] = "resource_group"
    except Exception as exc:
        log.warning("[hierarchy_tree] RG query failed: %s", exc)
        rg_rows = [{"_level": "resource_group", "_error": str(exc)}]

    # 4. Resource counts per type per subscription (lighter than all_resources)
    try:
        res_rows = await query_resource_graph(
            creds, ARG_TEMPLATES["resources_by_subscription"], top=1000,
        )
        for r in res_rows:
            r["_level"] = "resource_summary"
    except Exception as exc:
        log.warning("[hierarchy_tree] Resources query failed: %s", exc)
        res_rows = [{"_level": "resource_summary", "_error": str(exc)}]

    # Stitch into a single ordered result
    all_rows = mg_rows + sub_rows + rg_rows + res_rows
    return {
        "source": "composite",
        "query_used": "hierarchy_tree (management_groups + subscriptions + resource_groups + resources_by_subscription)",
        "results": all_rows,
        "count": len(all_rows),
        "_tree_hint": {
            "management_groups": len(mg_rows),
            "subscriptions": len(sub_rows),
            "resource_groups": len(rg_rows),
            "resource_summaries": len(res_rows),
        },
    }


# ---------------------------------------------------------------------------
# security_snapshot — combined security posture view
# ---------------------------------------------------------------------------

async def security_snapshot(
    creds: ComplianceCredentials, top: int = 100,
) -> dict[str, Any]:
    """Combined security posture snapshot.

    Queries: NSGs with open rules, public IPs, unencrypted VMs, storage with
    public access, risky users, and Defender secure score.
    """
    templates_to_run = [
        "nsg_open_rules",
        "public_ips",
        "vms_without_disk_encryption",
        "storage_public_access",
        "secure_score",
    ]

    all_rows: list[dict] = []
    for tpl in templates_to_run:
        try:
            rows = await query_resource_graph(creds, ARG_TEMPLATES[tpl], top=top)
            for r in rows:
                r["_queryTemplate"] = tpl
            all_rows.extend(rows)
        except Exception as exc:
            log.warning("[security_snapshot] %s failed: %s", tpl, exc)
            all_rows.append({"_queryTemplate": tpl, "_error": str(exc)})

    # Also fetch risky users from Entra
    try:
        entra_result = await _run_entra_query(creds, "risky_users", "risky users", top)
        for r in entra_result.get("results", []):
            r["_queryTemplate"] = "risky_users"
        all_rows.extend(entra_result.get("results", []))
    except Exception as exc:
        log.warning("[security_snapshot] risky_users failed: %s", exc)
        all_rows.append({"_queryTemplate": "risky_users", "_error": str(exc)})

    return {
        "source": "composite",
        "query_used": "security_snapshot (" + ", ".join(templates_to_run) + ", risky_users)",
        "results": all_rows,
        "count": len(all_rows),
    }


# ---------------------------------------------------------------------------
# resource_drill_down — subscription → RGs → all resources with details
# ---------------------------------------------------------------------------

async def resource_drill_down(
    creds: ComplianceCredentials, top: int = 200,
) -> dict[str, Any]:
    """Deep resource inventory: subscriptions → resource groups → all resources."""
    all_rows: list[dict] = []

    # Subscriptions
    try:
        sub_rows = await query_resource_graph(
            creds, ARG_TEMPLATES["subscriptions"], top=top,
        )
        for r in sub_rows:
            r["_queryTemplate"] = "subscriptions"
        all_rows.extend(sub_rows)
    except Exception as exc:
        log.warning("[resource_drill_down] subscriptions failed: %s", exc)

    # Resource groups
    try:
        rg_rows = await query_resource_graph(
            creds, ARG_TEMPLATES["resource_groups"], top=1000,
        )
        for r in rg_rows:
            r["_queryTemplate"] = "resource_groups"
        all_rows.extend(rg_rows)
    except Exception as exc:
        log.warning("[resource_drill_down] resource_groups failed: %s", exc)

    # All resources
    try:
        res_rows = await query_resource_graph(
            creds, ARG_TEMPLATES["all_resources"], top=1000,
        )
        for r in res_rows:
            r["_queryTemplate"] = "all_resources"
        all_rows.extend(res_rows)
    except Exception as exc:
        log.warning("[resource_drill_down] all_resources failed: %s", exc)

    return {
        "source": "composite",
        "query_used": "resource_drill_down (subscriptions + resource_groups + all_resources)",
        "results": all_rows,
        "count": len(all_rows),
    }
