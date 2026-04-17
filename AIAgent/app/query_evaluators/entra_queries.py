"""Entra ID (MS Graph) query functions."""

from __future__ import annotations
from typing import Any
from app.auth import ComplianceCredentials
from app.collectors.base import paginate_graph, AccessDeniedError
from app.logger import log

# ---------------------------------------------------------------------------
# MS Graph queries — Entra ID
# ---------------------------------------------------------------------------

async def query_entra_users(
    creds: ComplianceCredentials,
    filter_expr: str = "",
    select: list[str] | None = None,
    top: int = 100,
) -> list[dict]:
    """Query Entra ID users with optional OData filter."""
    graph = creds.get_graph_client()
    from msgraph.generated.users.users_request_builder import UsersRequestBuilder
    config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration()
    params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters()
    if filter_expr:
        params.filter = filter_expr
    if select:
        params.select = select
    else:
        params.select = [
            "id", "displayName", "userPrincipalName", "accountEnabled",
            "createdDateTime", "lastSignInDateTime", "userType",
        ]
    params.top = min(top, 999)
    config.query_parameters = params

    try:
        response = await graph.users.get(request_configuration=config)
        results = []
        if response and response.value:
            for u in response.value:
                results.append({
                    "id": u.id,
                    "displayName": u.display_name,
                    "userPrincipalName": u.user_principal_name,
                    "accountEnabled": u.account_enabled,
                    "userType": u.user_type,
                    "createdDateTime": str(u.created_date_time) if u.created_date_time else None,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Entra user query failed: %s", exc)
        raise


async def query_entra_groups(
    creds: ComplianceCredentials,
    filter_expr: str = "",
    top: int = 100,
) -> list[dict]:
    """Query Entra ID groups."""
    graph = creds.get_graph_client()
    from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder
    config = GroupsRequestBuilder.GroupsRequestBuilderGetRequestConfiguration()
    params = GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters()
    if filter_expr:
        params.filter = filter_expr
    params.select = ["id", "displayName", "groupTypes", "membershipRule", "securityEnabled"]
    params.top = min(top, 999)
    config.query_parameters = params

    try:
        response = await graph.groups.get(request_configuration=config)
        results = []
        if response and response.value:
            for g in response.value:
                results.append({
                    "id": g.id,
                    "displayName": g.display_name,
                    "groupTypes": list(g.group_types or []),
                    "securityEnabled": g.security_enabled,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Entra group query failed: %s", exc)
        raise


async def query_entra_apps(
    creds: ComplianceCredentials,
    filter_expr: str = "",
    top: int = 100,
) -> list[dict]:
    """Query Entra ID app registrations."""
    graph = creds.get_graph_client()
    from msgraph.generated.applications.applications_request_builder import ApplicationsRequestBuilder
    config = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetRequestConfiguration()
    params = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters()
    if filter_expr:
        params.filter = filter_expr
    params.select = ["id", "displayName", "appId", "signInAudience", "createdDateTime"]
    params.top = min(top, 999)
    config.query_parameters = params

    try:
        response = await graph.applications.get(request_configuration=config)
        results = []
        if response and response.value:
            for a in response.value:
                results.append({
                    "id": a.id,
                    "displayName": a.display_name,
                    "appId": a.app_id,
                    "signInAudience": a.sign_in_audience,
                    "createdDateTime": str(a.created_date_time) if a.created_date_time else None,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Entra app query failed: %s", exc)
        raise


async def query_entra_service_principals(
    creds: ComplianceCredentials,
    filter_expr: str = "",
    top: int = 100,
) -> list[dict]:
    """Query Entra ID service principals."""
    graph = creds.get_graph_client()
    from msgraph.generated.service_principals.service_principals_request_builder import ServicePrincipalsRequestBuilder
    config = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetRequestConfiguration()
    params = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters()
    if filter_expr:
        params.filter = filter_expr
    params.select = ["id", "displayName", "appId", "servicePrincipalType", "accountEnabled"]
    params.top = min(top, 999)
    config.query_parameters = params

    try:
        response = await graph.service_principals.get(request_configuration=config)
        results = []
        if response and response.value:
            for sp in response.value:
                results.append({
                    "id": sp.id,
                    "displayName": sp.display_name,
                    "appId": sp.app_id,
                    "servicePrincipalType": sp.service_principal_type,
                    "accountEnabled": sp.account_enabled,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Entra service principal query failed: %s", exc)
        raise


async def query_entra_directory_roles(
    creds: ComplianceCredentials,
) -> list[dict]:
    """List active Entra directory roles with full member details (UPN, assignment type, via-group)."""
    graph = creds.get_graph_client()
    try:
        roles_resp = await graph.directory_roles.get()
        results = []
        if roles_resp and roles_resp.value:
            for role in roles_resp.value:
                members_resp = await graph.directory_roles.by_directory_role_id(role.id).members.get()
                member_list = []
                if members_resp and members_resp.value:
                    for m in members_resp.value:
                        odata_type = getattr(m, "odata_type", "") or ""
                        if "user" in odata_type.lower():
                            member_list.append({
                                "userId": m.id,
                                "displayName": getattr(m, "display_name", None),
                                "userPrincipalName": getattr(m, "user_principal_name", None),
                                "assignmentType": "Direct",
                                "viaGroup": None,
                            })
                        elif "group" in odata_type.lower():
                            # Expand group members to show transitive role holders
                            grp_name = getattr(m, "display_name", m.id)
                            try:
                                grp_members = await graph.groups.by_group_id(m.id).members.get()
                                if grp_members and grp_members.value:
                                    for gm in grp_members.value:
                                        gm_type = getattr(gm, "odata_type", "") or ""
                                        if "user" in gm_type.lower():
                                            member_list.append({
                                                "userId": gm.id,
                                                "displayName": getattr(gm, "display_name", None),
                                                "userPrincipalName": getattr(gm, "user_principal_name", None),
                                                "assignmentType": "Via Group",
                                                "viaGroup": grp_name,
                                            })
                            except Exception:
                                member_list.append({
                                    "userId": m.id,
                                    "displayName": grp_name,
                                    "userPrincipalName": None,
                                    "assignmentType": "Via Group (unexpanded)",
                                    "viaGroup": grp_name,
                                })
                        elif "servicePrincipal" in odata_type.lower():
                            member_list.append({
                                "userId": m.id,
                                "displayName": getattr(m, "display_name", None),
                                "userPrincipalName": None,
                                "assignmentType": "ServicePrincipal",
                                "viaGroup": None,
                            })
                results.append({
                    "id": role.id,
                    "displayName": role.display_name,
                    "roleTemplateId": role.role_template_id,
                    "memberCount": len(member_list),
                    "members": member_list,
                })
        return results
    except Exception as exc:
        log.warning("Entra roles query failed: %s", exc)
        raise


async def query_entra_admin_users(
    creds: ComplianceCredentials,
) -> list[dict]:
    """Return a flat user-centric view of all users with administrative Entra roles.

    Returns rows like: {userPrincipalName, displayName, roleName, assignmentType, viaGroup}
    This is the direct answer to 'list users with admin roles'.
    """
    roles_data = await query_entra_directory_roles(creds)
    user_rows: list[dict] = []
    seen: set[tuple[str, str]] = set()  # (userId, roleName) dedup

    for role in roles_data:
        role_name = role.get("displayName", "Unknown")
        for member in role.get("members", []):
            upn = member.get("userPrincipalName")
            uid = member.get("userId", "")
            key = (uid, role_name)
            if key in seen:
                continue
            seen.add(key)
            user_rows.append({
                "userPrincipalName": upn or member.get("displayName", uid),
                "displayName": member.get("displayName", ""),
                "userId": uid,
                "roleName": role_name,
                "assignmentType": member.get("assignmentType", "Direct"),
                "viaGroup": member.get("viaGroup") or "",
            })

    # Sort by role name then UPN for clean output
    user_rows.sort(key=lambda r: (r["roleName"], r["userPrincipalName"] or ""))
    return user_rows


async def query_entra_conditional_access(
    creds: ComplianceCredentials,
) -> list[dict]:
    """List conditional access policies."""
    graph = creds.get_graph_client()
    try:
        policies = await graph.identity.conditional_access.policies.get()
        results = []
        if policies and policies.value:
            for p in policies.value:
                results.append({
                    "id": p.id,
                    "displayName": p.display_name,
                    "state": p.state.value if p.state else "unknown",
                    "createdDateTime": str(p.created_date_time) if p.created_date_time else None,
                })
        return results
    except Exception as exc:
        log.warning("Entra CA query failed: %s", exc)
        raise


# ── New Entra queries (v40-query) ──────────────────────────────

async def query_entra_risky_users(
    creds: ComplianceCredentials,
    top: int = 100,
) -> list[dict]:
    """List Entra ID risky users from Identity Protection."""
    graph = creds.get_graph_client()
    try:
        response = await graph.identity_protection.risky_users.get()
        results = []
        if response and response.value:
            for u in response.value:
                results.append({
                    "id": u.id,
                    "userDisplayName": u.user_display_name,
                    "userPrincipalName": u.user_principal_name,
                    "riskLevel": u.risk_level.value if u.risk_level else None,
                    "riskState": u.risk_state.value if u.risk_state else None,
                    "riskDetail": u.risk_detail.value if u.risk_detail else None,
                    "riskLastUpdatedDateTime": str(u.risk_last_updated_date_time) if u.risk_last_updated_date_time else None,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Entra risky users query failed: %s", exc)
        return [{"error": f"Risky users query failed (may require IdentityRiskyUser.Read.All): {exc}"}]


async def query_entra_named_locations(
    creds: ComplianceCredentials,
) -> list[dict]:
    """List Entra ID named locations."""
    graph = creds.get_graph_client()
    try:
        response = await graph.identity.conditional_access.named_locations.get()
        results = []
        if response and response.value:
            for loc in response.value:
                entry: dict[str, Any] = {
                    "id": loc.id,
                    "displayName": loc.display_name,
                    "odataType": getattr(loc, "odata_type", None),
                    "createdDateTime": str(loc.created_date_time) if loc.created_date_time else None,
                }
                # IP named location
                if hasattr(loc, "ip_ranges") and loc.ip_ranges:
                    entry["ipRanges"] = [getattr(r, "cidr_address", str(r)) for r in loc.ip_ranges]
                    entry["isTrusted"] = getattr(loc, "is_trusted", None)
                # Country named location
                if hasattr(loc, "countries_and_regions") and loc.countries_and_regions:
                    entry["countriesAndRegions"] = loc.countries_and_regions
                results.append(entry)
        return results
    except Exception as exc:
        log.warning("Entra named locations query failed: %s", exc)
        raise


async def query_entra_auth_methods_policy(
    creds: ComplianceCredentials,
) -> list[dict]:
    """Get authentication methods policy configuration."""
    graph = creds.get_graph_client()
    try:
        policy = await graph.policies.authentication_methods_policy.get()
        results = []
        if policy and policy.authentication_method_configurations:
            for m in policy.authentication_method_configurations:
                results.append({
                    "id": m.id,
                    "odataType": getattr(m, "odata_type", None),
                    "state": m.state.value if m.state else None,
                })
        return results
    except Exception as exc:
        log.warning("Entra auth methods policy query failed: %s", exc)
        return [{"error": f"Auth methods policy query failed: {exc}"}]


async def query_entra_role_assignments_pim(
    creds: ComplianceCredentials,
    top: int = 200,
) -> list[dict]:
    """List PIM-eligible role assignments."""
    graph = creds.get_graph_client()
    try:
        response = await graph.role_management.directory.role_eligibility_schedule_instances.get()
        results = []
        if response and response.value:
            for a in response.value:
                results.append({
                    "id": a.id,
                    "principalId": a.principal_id,
                    "roleDefinitionId": a.role_definition_id,
                    "directoryScopeId": a.directory_scope_id,
                    "startDateTime": str(a.start_date_time) if a.start_date_time else None,
                    "endDateTime": str(a.end_date_time) if a.end_date_time else None,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Entra PIM query failed: %s", exc)
        return [{"error": f"PIM query failed (may require RoleEligibilitySchedule.Read.Directory): {exc}"}]


# ---------------------------------------------------------------------------
# Resource detail drill-down
# ---------------------------------------------------------------------------
