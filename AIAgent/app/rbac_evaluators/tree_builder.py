"""Phase 1 & 4: Management-group hierarchy builder and subscription attachment."""

from __future__ import annotations

from azure.mgmt.managementgroups.aio import ManagementGroupsAPI
from app.auth import ComplianceCredentials
from app.logger import log


# ── Phase 1: MG hierarchy ───────────────────────────────────────────────

def _walk_mg_children(children) -> list[dict]:
    """Recursively convert MG child info objects to tree nodes."""
    nodes = []
    if not children:
        return nodes
    for child in children:
        ctype = getattr(child, "child_type", "") or ""
        child_id = getattr(child, "child_id", "") or getattr(child, "id", "") or ""
        child_name = getattr(child, "name", "") or child_id.rsplit("/", 1)[-1]
        display = getattr(child, "display_name", "") or child_name
        if "managementGroups" in ctype:
            nodes.append({
                "id": child_id,
                "name": child_name,
                "display_name": display,
                "type": "ManagementGroup",
                "children": _walk_mg_children(getattr(child, "children", None)),
                "assignments": [],
                "eligible": [],
            })
        elif "subscriptions" in ctype.lower() or "/subscriptions" in child_id.lower():
            nodes.append({
                "id": child_id,
                "name": child_name,
                "display_name": display,
                "type": "Subscription",
                "assignments": [],
                "eligible": [],
                "resource_groups": [],
            })
    return nodes


async def build_mg_tree(creds: ComplianceCredentials) -> dict:
    """Build the management-group tree starting from the tenant root."""
    tree = {
        "id": "",
        "name": "Tenant Root Group",
        "display_name": "Tenant Root Group",
        "type": "ManagementGroup",
        "children": [],
        "assignments": [],
        "eligible": [],
    }
    try:
        mg_client = ManagementGroupsAPI(credential=creds.credential)
        try:
            root_id = creds.tenant_id
            if not root_id:
                async for mg in mg_client.management_groups.list():
                    tid = getattr(mg, "tenant_id", "")
                    if tid:
                        root_id = tid
                        break
                    root_id = mg.name
                    break
            if root_id:
                root = await mg_client.management_groups.get(
                    root_id, expand="children", recurse=True,
                )
                tree["id"] = root.id or f"/providers/Microsoft.Management/managementGroups/{root_id}"
                tree["name"] = root.name or root_id
                tree["display_name"] = root.display_name or "Tenant Root Group"
                tree["children"] = _walk_mg_children(getattr(root, "children", None))
                log.info("[RbacTree] MG hierarchy built from root %s", root_id)
        except Exception as exc:
            log.warning("[RbacTree] Could not expand MG tree (falling back to flat list): %s", exc)
            async for mg in mg_client.management_groups.list():
                tree["children"].append({
                    "id": mg.id or "",
                    "name": mg.name or "",
                    "display_name": mg.display_name or mg.name or "",
                    "type": "ManagementGroup",
                    "children": [],
                    "assignments": [],
                    "eligible": [],
                })

        # Supplementary: ensure every accessible MG is in the tree.
        try:
            tree_mg_names: set[str] = set()

            def _collect_mg_names(node: dict):
                if node.get("type") == "ManagementGroup":
                    tree_mg_names.add(node.get("name", ""))
                for ch in node.get("children", []):
                    _collect_mg_names(ch)

            _collect_mg_names(tree)

            added = 0
            async for mg in mg_client.management_groups.list():
                mg_name = mg.name or ""
                if mg_name and mg_name not in tree_mg_names and mg_name != tree.get("name", ""):
                    tree["children"].append({
                        "id": mg.id or "",
                        "name": mg_name,
                        "display_name": mg.display_name or mg_name,
                        "type": "ManagementGroup",
                        "children": [],
                        "assignments": [],
                        "eligible": [],
                    })
                    tree_mg_names.add(mg_name)
                    added += 1
            if added:
                log.info("[RbacTree] Added %d MGs from supplementary listing", added)
        except Exception as exc:
            log.warning("[RbacTree] Supplementary MG listing failed: %s", exc)

        await mg_client.close()
    except Exception as exc:
        log.warning("[RbacTree] MG collection failed: %s", exc)
    return tree


# ── Phase 4: Attach subs to tree ────────────────────────────────────────

def attach_subs_to_tree(tree: dict, sub_nodes: dict[str, dict]):
    """Place subscription nodes into the MG tree at the correct position."""
    placed: set[str] = set()

    def _place(node: dict):
        new_children = []
        for child in node.get("children", []):
            if child["type"] == "Subscription":
                sub_id = child["name"]
                if sub_id in sub_nodes:
                    enriched = sub_nodes[sub_id]
                    child["assignments"] = enriched["assignments"]
                    child["eligible"] = enriched["eligible"]
                    child["resource_groups"] = enriched["resource_groups"]
                    placed.add(sub_id)
                new_children.append(child)
            else:
                _place(child)
                new_children.append(child)
        node["children"] = new_children

    _place(tree)

    for sub_id, snode in sub_nodes.items():
        if sub_id not in placed:
            tree["children"].append(snode)
