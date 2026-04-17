"""Phase 5 & 6: Principal resolution, sub-type enrichment, and group expansion."""

from __future__ import annotations

import asyncio
from app.auth import ComplianceCredentials
from app.logger import log


# ── Phase 5: Resolve principal display names ────────────────────────────

async def resolve_principals(creds: ComplianceCredentials, ids: set[str]) -> dict[str, dict]:
    """Batch-resolve principal IDs to display names via Graph getByIds."""
    principals: dict[str, dict] = {}
    if not ids:
        return principals
    id_list = [pid for pid in ids if pid]
    if not id_list:
        return principals
    try:
        graph = creds.get_graph_client()
        from msgraph.generated.directory_objects.get_by_ids.get_by_ids_post_request_body import (
            GetByIdsPostRequestBody,
        )
        for i in range(0, len(id_list), 1000):
            batch = id_list[i : i + 1000]
            body = GetByIdsPostRequestBody()
            body.ids = batch
            body.types = ["user", "group", "servicePrincipal"]
            result = await graph.directory_objects.get_by_ids.post(body)
            if result and result.value:
                for obj in result.value:
                    odata = getattr(obj, "odata_type", "") or ""
                    pid = getattr(obj, "id", "") or ""
                    dname = getattr(obj, "display_name", "") or pid
                    if "user" in odata.lower():
                        principals[pid] = {
                            "display_name": dname,
                            "type": "User",
                            "upn": getattr(obj, "user_principal_name", "") or "",
                        }
                    elif "group" in odata.lower():
                        principals[pid] = {
                            "display_name": dname,
                            "type": "Group",
                            "members": [],
                        }
                    elif "serviceprincipal" in odata.lower():
                        principals[pid] = {
                            "display_name": getattr(obj, "app_display_name", "") or dname,
                            "type": "ServicePrincipal",
                            "app_id": getattr(obj, "app_id", "") or "",
                        }
                    else:
                        principals[pid] = {"display_name": dname, "type": "Unknown"}
            if i + 1000 < len(id_list):
                await asyncio.sleep(0.5)
        log.info("[RbacTree] Resolved %d / %d principals", len(principals), len(id_list))
    except Exception as exc:
        log.warning("[RbacTree] Principal resolution failed: %s", exc)
    for pid in id_list:
        if pid not in principals:
            principals[pid] = {"display_name": pid, "type": "Unknown"}
    return principals


# ── Phase 5 helper: backfill Unknown types from ARM data ────────────────

def backfill_principal_types(tree: dict, principals: dict) -> None:
    """Walk the tree and use assignment principal_type to fix 'Unknown' entries."""
    def _collect_assignments(node: dict) -> list[dict]:
        out = list(node.get("assignments", []))
        out.extend(node.get("eligible", []))
        for rg in node.get("resource_groups", []):
            out.extend(rg.get("assignments", []))
            for res in rg.get("resources", []):
                out.extend(res.get("assignments", []))
        for child in node.get("children", []):
            out.extend(_collect_assignments(child))
        return out

    for a in _collect_assignments(tree):
        pid = a.get("principal_id", "")
        ptype = a.get("principal_type", "")
        if pid and ptype and ptype != "Unknown":
            entry = principals.get(pid)
            if entry and entry.get("type") == "Unknown":
                entry["type"] = ptype


# ── Phase 5b: Enrich principal sub-types ────────────────────────────────

_SP_SUBTYPE_MAP = {
    "Application": "Application",
    "ManagedIdentity": "ManagedIdentity",
    "Legacy": "Legacy",
    "SocialIdp": "SocialIdp",
}


async def enrich_principal_subtypes(creds: ComplianceCredentials, principals: dict[str, dict]):
    """Classify principals into sub-types (e.g. ManagedIdentity, Guest User).

    Updates each entry in *principals* with a ``sub_type`` field:
    - User  → ``"Member"`` or ``"Guest"``
    - Group → ``"Group"``
    - ServicePrincipal → ``"Application"`` | ``"ManagedIdentity"`` | ``"Legacy"``
      (ManagedIdentity further annotated with ``mi_type``:
       ``"SystemAssigned"`` or ``"UserAssigned"``)
    - Unknown → ``"Unknown"``
    """
    for pid, info in principals.items():
        if info.get("type") == "User":
            upn = info.get("upn", "")
            info["sub_type"] = "Guest" if "#EXT#" in upn else "Member"
        elif info.get("type") == "Group":
            info["sub_type"] = "Group"
        elif info.get("type") == "Unknown":
            info["sub_type"] = "Unknown"

    sp_ids = [pid for pid, info in principals.items() if info.get("type") == "ServicePrincipal"]
    if not sp_ids:
        return

    sem = asyncio.Semaphore(10)

    async def _get_sp_detail(graph, sp_id: str):
        async with sem:
            try:
                sp = await graph.service_principals.by_service_principal_id(sp_id).get()
                return (
                    sp_id,
                    getattr(sp, "service_principal_type", None) or "",
                    list(getattr(sp, "alternative_names", None) or []),
                )
            except Exception:
                return sp_id, "", []

    try:
        graph = creds.get_graph_client()
        results = await asyncio.gather(*[_get_sp_detail(graph, sid) for sid in sp_ids])
        enriched = 0
        for sp_id, sp_type, alt_names in results:
            if sp_id not in principals:
                continue
            sub = _SP_SUBTYPE_MAP.get(sp_type, "Application")
            principals[sp_id]["sub_type"] = sub
            if sub == "ManagedIdentity":
                is_user = any("isExplicit=True" in str(a) for a in alt_names)
                principals[sp_id]["mi_type"] = "UserAssigned" if is_user else "SystemAssigned"
            enriched += 1
        log.info("[RbacTree] Enriched %d / %d service principal sub-types", enriched, len(sp_ids))
    except Exception as exc:
        log.warning("[RbacTree] SP sub-type enrichment failed: %s", exc)
        for sp_id in sp_ids:
            if sp_id in principals and "sub_type" not in principals[sp_id]:
                principals[sp_id]["sub_type"] = "Application"


# ── Phase 6: Expand group memberships ───────────────────────────────────

async def expand_groups(creds: ComplianceCredentials, principals: dict[str, dict]):
    """For each group principal, fetch its transitive members via Graph."""
    groups = [pid for pid, info in principals.items() if info.get("type") == "Group"]
    if not groups:
        return

    async def _get_group_members(graph, gid: str) -> list:
        from msgraph.generated.groups.item.transitive_members.transitive_members_request_builder import TransitiveMembersRequestBuilder
        from kiota_abstractions.headers_collection import HeadersCollection
        headers = HeadersCollection()
        headers.add("ConsistencyLevel", "eventual")
        cfg = TransitiveMembersRequestBuilder.TransitiveMembersRequestBuilderGetRequestConfiguration(
            headers=headers,
            query_parameters=TransitiveMembersRequestBuilder.TransitiveMembersRequestBuilderGetQueryParameters(
                count=True,
                top=999,
            ),
        )
        result = await graph.groups.by_group_id(gid).transitive_members.get(request_configuration=cfg)
        items = list(result.value) if result and result.value else []
        while result and result.odata_next_link:
            result = await graph.groups.by_group_id(gid).transitive_members.with_url(
                result.odata_next_link
            ).get(request_configuration=cfg)
            if result and result.value:
                items.extend(result.value)
        return items

    def _parse_member(m) -> dict:
        odata = getattr(m, "odata_type", "") or ""
        mid = getattr(m, "id", "") or ""
        mname = getattr(m, "display_name", "") or mid
        mtype = "Unknown"
        if "user" in odata.lower():
            mtype = "User"
        elif "group" in odata.lower():
            mtype = "Group"
        elif "serviceprincipal" in odata.lower():
            mtype = "ServicePrincipal"
        return {
            "id": mid,
            "display_name": mname,
            "type": mtype,
            "upn": getattr(m, "user_principal_name", "") or "",
        }

    try:
        graph = creds.get_graph_client()
        for gid in groups:
            try:
                raw_members = await _get_group_members(graph, gid)
                member_list = [_parse_member(m) for m in raw_members]
                for entry in member_list:
                    if entry["type"] == "Group":
                        try:
                            sub_raw = await _get_group_members(graph, entry["id"])
                            entry["members"] = [_parse_member(sm) for sm in sub_raw]
                        except Exception:
                            pass
                principals[gid]["members"] = member_list
            except Exception as exc:
                log.warning("  [RbacTree] Group %s member expansion failed: %s", gid, exc)
        log.info("[RbacTree] Expanded %d groups", len(groups))
    except Exception as exc:
        log.warning("[RbacTree] Group expansion failed: %s", exc)
