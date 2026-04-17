"""
Entra Users Collector
Aggregate user stats: total, member, guest, synced.
"""

from __future__ import annotations
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from app.models import Source
from app.collectors.base import run_collector, make_evidence, paginate_graph
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="users", plane="control", source="entra", priority=20)
async def collect_entra_users(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()

        # Get user counts by type
        config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
            query_parameters=UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "userType", "onPremisesSyncEnabled", "accountEnabled"],
                top=999,
                count=True,
            ),
        )
        config.headers.add("ConsistencyLevel", "eventual")

        users = await paginate_graph(graph.users, top=999)

        total = len(users)
        members = sum(1 for u in users if getattr(u, "user_type", "Member") == "Member")
        guests = sum(1 for u in users if getattr(u, "user_type", "") == "Guest")
        synced = sum(1 for u in users if getattr(u, "on_premises_sync_enabled", False))
        enabled = sum(1 for u in users if getattr(u, "account_enabled", True))
        disabled = total - enabled

        evidence.append(make_evidence(
            source=Source.ENTRA, collector="EntraUsers",
            evidence_type="entra-user-summary",
            description="Entra ID user population summary",
            data={
                "TotalUsers": total,
                "MemberUsers": members,
                "GuestUsers": guests,
                "SyncedUsers": synced,
                "EnabledUsers": enabled,
                "DisabledUsers": disabled,
                "GuestToMemberRatio": round(guests / members, 4) if members > 0 else 0,
            },
        ))

        # Groups
        groups = await paginate_graph(graph.groups)
        total_groups = len(groups)
        security_groups = sum(1 for g in groups if getattr(g, "security_enabled", False))
        m365_groups = sum(1 for g in groups if getattr(g, "group_types", None) and "Unified" in getattr(g, "group_types", []))
        synced_groups = sum(1 for g in groups if getattr(g, "on_premises_sync_enabled", False))

        evidence.append(make_evidence(
            source=Source.ENTRA, collector="EntraUsers",
            evidence_type="entra-group-summary",
            description="Entra ID group summary",
            data={
                "TotalGroups": total_groups,
                "SecurityGroups": security_groups,
                "M365Groups": m365_groups,
                "SyncedGroups": synced_groups,
            },
        ))

        log.info("  [EntraUsers] %d users, %d groups", total, total_groups)
        return evidence

    return (await run_collector("EntraUsers", Source.ENTRA, _collect)).data
