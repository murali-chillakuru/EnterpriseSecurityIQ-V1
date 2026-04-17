"""ARG query primitives and pre-built templates."""

from __future__ import annotations
from typing import Any
from azure.mgmt.resourcegraph.aio import ResourceGraphClient
from azure.mgmt.resourcegraph.models import (
    QueryRequest, QueryRequestOptions, ResultFormat,
)
from app.auth import ComplianceCredentials
from app.logger import log



# ---------------------------------------------------------------------------
# Azure Resource Graph queries
# ---------------------------------------------------------------------------

async def query_resource_graph(
    creds: ComplianceCredentials,
    kql: str,
    subscriptions: list[str] | None = None,
    top: int = 100,
    management_group_ids: list[str] | None = None,
) -> list[dict]:
    """Execute a KQL query against Azure Resource Graph.

    Automatically follows ``$skipToken`` pagination to retrieve all matching
    records, not just the first page.

    Pass *management_group_ids* to scope the query at the management-group
    level (required for ``ResourceContainers`` queries that target
    ``microsoft.management/managementgroups``).  When provided, the
    *subscriptions* parameter is ignored.
    """
    # Management-group-scoped queries don't need subscription IDs
    if not management_group_ids:
        if not subscriptions:
            subs = await creds.list_subscriptions()
            subscriptions = [s["subscription_id"] for s in subs]
        if not subscriptions:
            return []

    client = ResourceGraphClient(creds.credential)
    try:
        rows: list[dict] = []
        skip_token: str | None = None

        while True:
            options = QueryRequestOptions(
                result_format=ResultFormat.OBJECT_ARRAY,
                top=top,
                skip_token=skip_token,
            )
            if management_group_ids:
                request = QueryRequest(
                    management_groups=management_group_ids,
                    query=kql, options=options,
                )
            else:
                request = QueryRequest(
                    subscriptions=subscriptions, query=kql, options=options,
                )
            response = await client.resources(request)
            if response.data:
                for item in response.data:
                    rows.append(dict(item) if hasattr(item, "__iter__") else item)

            skip_token = getattr(response, "skip_token", None)
            if not skip_token:
                break

        return rows
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# ARG_TEMPLATES — now lives in cloud_explorer.arg_templates.
# Re-exported here for backward compat (query_engine shim, agent.py, tests).
# ---------------------------------------------------------------------------
from app.cloud_explorer.arg_templates import ARG_TEMPLATES  # noqa: F401

