"""Deterministic sorting for reproducible RBAC output."""

from __future__ import annotations


def sort_tree_deterministic(node: dict):
    """Recursively sort all lists in the tree for deterministic output.

    Sort keys:
    - children: (type, id)
    - assignments / eligible: (role_name, principal_id, scope)
    - resource_groups: (name)
    - resources: (id)
    """
    _ASSIGN_KEY = lambda a: (a.get("role_name", ""), a.get("principal_id", ""), a.get("scope", ""))
    if "children" in node:
        node["children"].sort(key=lambda c: (c.get("type", ""), c.get("id", "")))
    for key in ("assignments", "eligible"):
        if key in node and node[key]:
            node[key].sort(key=_ASSIGN_KEY)
    if node.get("resource_groups"):
        node["resource_groups"].sort(key=lambda rg: rg.get("name", ""))
        for rg in node["resource_groups"]:
            if rg.get("assignments"):
                rg["assignments"].sort(key=_ASSIGN_KEY)
            if rg.get("resources"):
                rg["resources"].sort(key=lambda r: r.get("id", ""))
                for res in rg["resources"]:
                    if res.get("assignments"):
                        res["assignments"].sort(key=_ASSIGN_KEY)
    for child in node.get("children", []):
        sort_tree_deterministic(child)


def sort_group_members_deterministic(principals: dict[str, dict]):
    """Sort group members by id for deterministic output."""
    for info in principals.values():
        members = info.get("members")
        if members:
            members.sort(key=lambda m: m.get("id", ""))
            for m in members:
                sub = m.get("members")
                if sub:
                    sub.sort(key=lambda s: s.get("id", ""))
