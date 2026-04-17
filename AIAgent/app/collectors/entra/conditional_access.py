"""
Entra Conditional Access Collector
"""

from __future__ import annotations
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="conditional_access", plane="control", source="entra", priority=40)
async def collect_entra_conditional_access(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()
        policies = await paginate_graph(graph.identity.conditional_access.policies)

        for p in policies:
            conditions = p.conditions or type("C", (), {"users": None, "applications": None})()
            grant = p.grant_controls or type("G", (), {"built_in_controls": []})()
            session = p.session_controls

            users_cond = conditions.users or type("U", (), {
                "include_users": [], "exclude_users": [],
                "include_groups": [], "include_roles": [],
            })()

            built_in = [c.value if hasattr(c, "value") else str(c)
                        for c in (grant.built_in_controls or [])]
            requires_mfa = "mfa" in built_in
            requires_compliant = "compliantDevice" in built_in
            targets_all = "All" in (getattr(users_cond, "include_users", []) or [])
            include_roles = getattr(users_cond, "include_roles", []) or []
            targets_admins = len(include_roles) > 0

            # Legacy auth detection
            client_app_types = []
            if hasattr(conditions, "client_app_types") and conditions.client_app_types:
                client_app_types = [
                    c.value if hasattr(c, "value") else str(c)
                    for c in conditions.client_app_types
                ]
            blocks_legacy_auth = (
                "block" in built_in
                and any(t in client_app_types for t in ("exchangeActiveSync", "other"))
            )

            # Location condition detection
            has_location_condition = False
            loc_cond = getattr(conditions, "locations", None)
            if loc_cond:
                include_locs = getattr(loc_cond, "include_locations", []) or []
                has_location_condition = len(include_locs) > 0

            # Authentication strength
            auth_strength = ""
            if hasattr(grant, "authentication_strength") and grant.authentication_strength:
                auth_strength = getattr(grant.authentication_strength, "display_name", "") or ""

            evidence.append(make_evidence(
                source=Source.ENTRA, collector="EntraConditionalAccess",
                evidence_type="entra-conditional-access-policy",
                description=f"CA: {p.display_name}",
                data={
                    "PolicyId": p.id,
                    "DisplayName": p.display_name,
                    "State": p.state.value if p.state else "disabled",
                    "RequiresMFA": requires_mfa,
                    "RequiresCompliantDevice": requires_compliant,
                    "TargetsAllUsers": targets_all,
                    "TargetsAdmins": targets_admins,
                    "IncludeUsers": list(getattr(users_cond, "include_users", []) or []),
                    "ExcludeUsers": list(getattr(users_cond, "exclude_users", []) or []),
                    "IncludeGroups": list(getattr(users_cond, "include_groups", []) or []),
                    "IncludeRoles": include_roles,
                    "GrantControls": built_in,
                    "SessionControls": str(session) if session else "",
                    "BlocksLegacyAuth": blocks_legacy_auth,
                    "HasLocationCondition": has_location_condition,
                    "ClientAppTypes": client_app_types,
                    "AuthenticationStrength": auth_strength,
                },
                resource_id=p.id or "", resource_type="ConditionalAccessPolicy",
            ))

        log.info("  [EntraConditionalAccess] %d policies", len(policies))
        return evidence

    return (await run_collector("EntraConditionalAccess", Source.ENTRA, _collect)).data
