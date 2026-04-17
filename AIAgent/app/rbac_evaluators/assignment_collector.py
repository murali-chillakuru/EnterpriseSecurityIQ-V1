"""Phase 2 & 3: Role-assignment collection at MG and subscription scopes."""

from __future__ import annotations

from azure.mgmt.authorization.aio import AuthorizationManagementClient
from azure.mgmt.resource.resources.aio import ResourceManagementClient
from app.collectors.base import paginate_arm, AccessDeniedError
from app.auth import ComplianceCredentials
from app.logger import log
from .helpers import scope_level, rg_from_scope, make_assignment


# ── Phase 2: MG-level assignments ───────────────────────────────────────

async def collect_mg_assignments(
    creds: ComplianceCredentials,
    tree: dict,
    subscriptions: list[dict],
    role_def_cache: dict,
    principal_ids: set,
):
    """Collect role assignments at each management-group scope."""
    if not subscriptions:
        return
    first_sub = subscriptions[0]["subscription_id"]
    try:
        auth_client = AuthorizationManagementClient(creds.credential, first_sub)
        await _collect_node_assignments(auth_client, tree, role_def_cache, principal_ids)
        await auth_client.close()
    except Exception as exc:
        log.warning("[RbacTree] MG assignment collection failed: %s", exc)


async def _collect_node_assignments(
    auth_client: AuthorizationManagementClient,
    node: dict,
    role_def_cache: dict,
    principal_ids: set,
):
    """Recursively collect assignments for a single MG node and its child MGs."""
    if node["type"] != "ManagementGroup":
        return
    scope = node["id"]
    if not scope:
        scope = f"/providers/Microsoft.Management/managementGroups/{node['name']}"
    try:
        raw = await paginate_arm(
            auth_client.role_assignments.list_for_scope(scope, filter="atScope()"),
        )
        for ra in raw:
            role_name, role_type = await _resolve_role_def(
                auth_client, ra.role_definition_id, role_def_cache,
            )
            node["assignments"].append(
                make_assignment(ra, role_name, role_type, "Active"),
            )
            if ra.principal_id:
                principal_ids.add(ra.principal_id)
        log.info("  [RbacTree] MG %s: %d assignments", node["display_name"], len(raw))
    except AccessDeniedError:
        log.warning("  [RbacTree] Access denied for MG scope %s", scope)
    except Exception as exc:
        log.warning("  [RbacTree] MG assignments for %s failed: %s", node["display_name"], exc)

    # PIM eligible at MG scope
    try:
        elig_raw = await paginate_arm(
            auth_client.role_eligibility_schedule_instances.list_for_scope(scope),
        )
        for er in elig_raw:
            role_name, role_type = await _resolve_role_def(
                auth_client, er.role_definition_id, role_def_cache,
            )
            node["eligible"].append(
                make_assignment(er, role_name, role_type, "Eligible"),
            )
            pid = getattr(er, "principal_id", "")
            if pid:
                principal_ids.add(pid)
    except Exception:
        pass  # PIM APIs often require additional licensing / permission

    for child in node.get("children", []):
        if child["type"] == "ManagementGroup":
            await _collect_node_assignments(auth_client, child, role_def_cache, principal_ids)


async def _resolve_role_def(
    auth_client: AuthorizationManagementClient,
    role_def_id: str | None,
    cache: dict,
) -> tuple[str, str]:
    """Resolve a role definition ID to (name, type), using cache."""
    if not role_def_id:
        return ("Unknown", "Unknown")
    if role_def_id in cache:
        return cache[role_def_id]
    try:
        rd = await auth_client.role_definitions.get_by_id(role_def_id)
        name = rd.role_name or role_def_id.rsplit("/", 1)[-1]
        rtype = rd.role_type or "BuiltInRole"
        cache[role_def_id] = (name, rtype)
        return (name, rtype)
    except Exception:
        fallback = role_def_id.rsplit("/", 1)[-1]
        cache[role_def_id] = (fallback, "Unknown")
        return (fallback, "Unknown")


# ── Phase 3: Per-subscription data ──────────────────────────────────────

async def collect_sub_data(
    creds: ComplianceCredentials,
    subscriptions: list[dict],
    role_def_cache: dict,
    principal_ids: set,
) -> dict[str, dict]:
    """Collect assignments, RGs, and resources for each subscription.
    Returns {subscription_id: node_dict}."""
    sub_nodes: dict[str, dict] = {}
    for sub in subscriptions:
        sub_id = sub["subscription_id"]
        sub_name = sub["display_name"]
        node: dict = {
            "id": f"/subscriptions/{sub_id}",
            "name": sub_id,
            "display_name": sub_name,
            "type": "Subscription",
            "assignments": [],
            "eligible": [],
            "resource_groups": [],
        }
        sub_nodes[sub_id] = node

        # ── Role assignments ──
        try:
            auth_client = AuthorizationManagementClient(creds.credential, sub_id)
            all_ra = await paginate_arm(auth_client.role_assignments.list_for_subscription())
            rg_assignments: dict[str, list] = {}
            for ra in all_ra:
                role_name, role_type = await _resolve_role_def(
                    auth_client, ra.role_definition_id, role_def_cache,
                )
                a = make_assignment(ra, role_name, role_type, "Active")
                if ra.principal_id:
                    principal_ids.add(ra.principal_id)
                lvl = a["scope_level"]
                if lvl == "Subscription":
                    node["assignments"].append(a)
                elif lvl in ("ResourceGroup", "Resource"):
                    rg_name = rg_from_scope(a["scope"])
                    rg_assignments.setdefault(rg_name, []).append(a)
                else:
                    node["assignments"].append(a)
            log.info("  [RbacTree] %s: %d total assignments", sub_name, len(all_ra))

            # ── PIM eligible ──
            try:
                pim_scope = f"/subscriptions/{sub_id}"
                elig_raw = await paginate_arm(
                    auth_client.role_eligibility_schedule_instances.list_for_scope(pim_scope),
                )
                for er in elig_raw:
                    role_name, role_type = await _resolve_role_def(
                        auth_client, er.role_definition_id, role_def_cache,
                    )
                    a = make_assignment(er, role_name, role_type, "Eligible")
                    pid = getattr(er, "principal_id", "")
                    if pid:
                        principal_ids.add(pid)
                    lvl = a["scope_level"]
                    if lvl == "Subscription":
                        node["eligible"].append(a)
                    else:
                        rg_name = rg_from_scope(a["scope"])
                        rg_assignments.setdefault(rg_name, []).append(a)
                log.info("  [RbacTree] %s: %d PIM eligible", sub_name, len(elig_raw))
            except Exception:
                pass  # PIM not available

            await auth_client.close()
        except AccessDeniedError:
            log.warning("  [RbacTree] Access denied for subscription %s", sub_name)
            continue
        except Exception as exc:
            log.warning("  [RbacTree] Assignments for %s failed: %s", sub_name, exc)
            continue

        # ── Resource groups and resources ──
        try:
            res_client = ResourceManagementClient(creds.credential, sub_id)
            rgs = await paginate_arm(res_client.resource_groups.list())
            resources = await paginate_arm(res_client.resources.list())
            await res_client.close()

            rg_resources: dict[str, list] = {}
            for r in resources:
                rg_name = rg_from_scope(r.id or "")
                rg_resources.setdefault(rg_name, []).append({
                    "id": r.id or "",
                    "name": r.name or "",
                    "display_name": r.name or "",
                    "resource_type": r.type or "",
                    "type": "Resource",
                    "location": r.location or "",
                    "assignments": [],
                })

            for rg in rgs:
                rg_name = rg.name or ""
                rg_node: dict = {
                    "id": rg.id or "",
                    "name": rg_name,
                    "display_name": rg_name,
                    "type": "ResourceGroup",
                    "assignments": [],
                    "resources": rg_resources.get(rg_name, []),
                }
                for a in rg_assignments.get(rg_name, []):
                    if a["scope_level"] == "ResourceGroup":
                        rg_node["assignments"].append(a)
                    else:
                        placed = False
                        for res in rg_node["resources"]:
                            if res["id"] and a["scope"].lower() == res["id"].lower():
                                res["assignments"].append(a)
                                placed = True
                                break
                        if not placed:
                            rg_node["assignments"].append(a)
                node["resource_groups"].append(rg_node)

            log.info("  [RbacTree] %s: %d RGs, %d resources", sub_name, len(rgs), len(resources))
        except Exception as exc:
            log.warning("  [RbacTree] Resources for %s failed: %s", sub_name, exc)

    return sub_nodes
