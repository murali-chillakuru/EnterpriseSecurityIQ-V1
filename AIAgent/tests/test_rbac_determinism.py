"""
Determinism tests for the RBAC Report pipeline.

These tests verify that given the same collected RBAC data (tree, principals),
the computation functions (_compute_stats, _compute_risks, _compute_rbac_score)
and the overall data structure produce identical results across multiple runs.

Each test documents a specific determinism gap or validates a fix.
"""

from __future__ import annotations

import copy
import json
import random
import pytest

from app.collectors.azure.rbac_collector import (
    _compute_stats,
    _compute_risks,
    _compute_rbac_score,
    _count_tree,
    _attach_subs_to_tree,
    _sort_tree_deterministic,
    _sort_group_members_deterministic,
    _scope_level,
    PRIVILEGED_ROLES,
)


# ─────────────────────────────────────────────────────────────────────────
# Helpers: build frozen RBAC data
# ─────────────────────────────────────────────────────────────────────────

def _make_frozen_assignment(
    *,
    ra_id: str,
    role_name: str,
    principal_id: str,
    scope: str,
    principal_type: str = "User",
    status: str = "Active",
    is_privileged: bool | None = None,
    is_custom: bool = False,
) -> dict:
    """Create a single role-assignment dict (same shape as _make_assignment)."""
    if is_privileged is None:
        is_privileged = role_name in PRIVILEGED_ROLES
    return {
        "id": ra_id,
        "role_name": role_name,
        "role_definition_id": f"/providers/Microsoft.Authorization/roleDefinitions/{ra_id.split('/')[-1]}",
        "principal_id": principal_id,
        "principal_type": principal_type,
        "scope": scope,
        "scope_level": _scope_level(scope),
        "status": status,
        "is_privileged": is_privileged,
        "is_custom": is_custom,
    }


def _build_frozen_tree() -> dict:
    """Build a realistic RBAC tree with 2 MGs, 3 subs, RGs, resources, and assignments.

    The tree deliberately includes multiple items at each level so that
    ordering issues surface.
    """
    # ── Principals ──
    # (referenced by ID in assignments)
    # user-aaa through user-ddd: regular users
    # sp-eee, sp-fff: service principals
    # grp-ggg: group with 25 members (triggers large-group risk)

    root_mg_scope = "/providers/Microsoft.Management/managementGroups/tenant-root"
    child_mg_scope = "/providers/Microsoft.Management/managementGroups/child-mg-1"
    sub1_scope = "/subscriptions/sub-1111"
    sub2_scope = "/subscriptions/sub-2222"
    sub3_scope = "/subscriptions/sub-3333"
    rg_alpha = f"{sub1_scope}/resourceGroups/rg-alpha"
    rg_beta = f"{sub1_scope}/resourceGroups/rg-beta"
    rg_gamma = f"{sub2_scope}/resourceGroups/rg-gamma"
    res_kv = f"{rg_alpha}/providers/Microsoft.KeyVault/vaults/kv-1"
    res_sa = f"{rg_beta}/providers/Microsoft.Storage/storageAccounts/sa-1"

    tree = {
        "id": root_mg_scope,
        "name": "tenant-root",
        "display_name": "Tenant Root Group",
        "type": "ManagementGroup",
        "children": [
            {
                "id": child_mg_scope,
                "name": "child-mg-1",
                "display_name": "Child MG One",
                "type": "ManagementGroup",
                "children": [
                    # sub-2222 is under child MG
                    {
                        "id": sub2_scope,
                        "name": "sub-2222",
                        "display_name": "Sub Two",
                        "type": "Subscription",
                        "assignments": [
                            _make_frozen_assignment(
                                ra_id=f"{sub2_scope}/providers/Microsoft.Authorization/roleAssignments/ra-20",
                                role_name="Owner",
                                principal_id="user-aaa",
                                scope=sub2_scope,
                            ),
                            _make_frozen_assignment(
                                ra_id=f"{sub2_scope}/providers/Microsoft.Authorization/roleAssignments/ra-21",
                                role_name="Contributor",
                                principal_id="sp-eee",
                                principal_type="ServicePrincipal",
                                scope=sub2_scope,
                            ),
                        ],
                        "eligible": [
                            _make_frozen_assignment(
                                ra_id=f"{sub2_scope}/providers/Microsoft.Authorization/roleAssignments/ra-22",
                                role_name="Owner",
                                principal_id="user-bbb",
                                scope=sub2_scope,
                                status="Eligible",
                            ),
                        ],
                        "resource_groups": [
                            {
                                "id": rg_gamma,
                                "name": "rg-gamma",
                                "display_name": "rg-gamma",
                                "type": "ResourceGroup",
                                "assignments": [
                                    _make_frozen_assignment(
                                        ra_id=f"{rg_gamma}/providers/Microsoft.Authorization/roleAssignments/ra-30",
                                        role_name="Reader",
                                        principal_id="user-ccc",
                                        scope=rg_gamma,
                                    ),
                                ],
                                "resources": [],
                            },
                        ],
                    },
                ],
                "assignments": [
                    _make_frozen_assignment(
                        ra_id=f"{child_mg_scope}/providers/Microsoft.Authorization/roleAssignments/ra-10",
                        role_name="Contributor",
                        principal_id="user-ddd",
                        scope=child_mg_scope,
                    ),
                ],
                "eligible": [],
            },
            # sub-1111 directly under root (placed by _attach_subs_to_tree or directly)
            {
                "id": sub1_scope,
                "name": "sub-1111",
                "display_name": "Sub One",
                "type": "Subscription",
                "assignments": [
                    _make_frozen_assignment(
                        ra_id=f"{sub1_scope}/providers/Microsoft.Authorization/roleAssignments/ra-01",
                        role_name="Owner",
                        principal_id="user-aaa",
                        scope=sub1_scope,
                    ),
                    _make_frozen_assignment(
                        ra_id=f"{sub1_scope}/providers/Microsoft.Authorization/roleAssignments/ra-02",
                        role_name="User Access Administrator",
                        principal_id="sp-fff",
                        principal_type="ServicePrincipal",
                        scope=sub1_scope,
                    ),
                    _make_frozen_assignment(
                        ra_id=f"{sub1_scope}/providers/Microsoft.Authorization/roleAssignments/ra-03",
                        role_name="Contributor",
                        principal_id="grp-ggg",
                        principal_type="Group",
                        scope=sub1_scope,
                    ),
                    _make_frozen_assignment(
                        ra_id=f"{sub1_scope}/providers/Microsoft.Authorization/roleAssignments/ra-04",
                        role_name="MyCustomRole",
                        principal_id="user-bbb",
                        scope=sub1_scope,
                        is_custom=True,
                    ),
                ],
                "eligible": [],
                "resource_groups": [
                    {
                        "id": rg_beta,
                        "name": "rg-beta",
                        "display_name": "rg-beta",
                        "type": "ResourceGroup",
                        "assignments": [
                            _make_frozen_assignment(
                                ra_id=f"{rg_beta}/providers/Microsoft.Authorization/roleAssignments/ra-06",
                                role_name="Contributor",
                                principal_id="user-ccc",
                                scope=rg_beta,
                            ),
                        ],
                        "resources": [
                            {
                                "id": res_sa,
                                "name": "sa-1",
                                "display_name": "sa-1",
                                "resource_type": "Microsoft.Storage/storageAccounts",
                                "type": "Resource",
                                "location": "eastus",
                                "assignments": [
                                    _make_frozen_assignment(
                                        ra_id=f"{res_sa}/providers/Microsoft.Authorization/roleAssignments/ra-07",
                                        role_name="Storage Blob Data Reader",
                                        principal_id="sp-eee",
                                        principal_type="ServicePrincipal",
                                        scope=res_sa,
                                    ),
                                ],
                            },
                        ],
                    },
                    {
                        "id": rg_alpha,
                        "name": "rg-alpha",
                        "display_name": "rg-alpha",
                        "type": "ResourceGroup",
                        "assignments": [
                            _make_frozen_assignment(
                                ra_id=f"{rg_alpha}/providers/Microsoft.Authorization/roleAssignments/ra-05",
                                role_name="Key Vault Administrator",
                                principal_id="user-bbb",
                                scope=rg_alpha,
                            ),
                        ],
                        "resources": [
                            {
                                "id": res_kv,
                                "name": "kv-1",
                                "display_name": "kv-1",
                                "resource_type": "Microsoft.KeyVault/vaults",
                                "type": "Resource",
                                "location": "eastus",
                                "assignments": [],
                            },
                        ],
                    },
                ],
            },
            # sub-3333 directly under root
            {
                "id": sub3_scope,
                "name": "sub-3333",
                "display_name": "Sub Three",
                "type": "Subscription",
                "assignments": [
                    _make_frozen_assignment(
                        ra_id=f"{sub3_scope}/providers/Microsoft.Authorization/roleAssignments/ra-40",
                        role_name="Owner",
                        principal_id="sp-fff",
                        principal_type="ServicePrincipal",
                        scope=sub3_scope,
                    ),
                ],
                "eligible": [],
                "resource_groups": [],
            },
        ],
        "assignments": [
            # Root MG-level Owner — critical risk
            _make_frozen_assignment(
                ra_id=f"{root_mg_scope}/providers/Microsoft.Authorization/roleAssignments/ra-00",
                role_name="Owner",
                principal_id="user-aaa",
                scope=root_mg_scope,
            ),
        ],
        "eligible": [],
    }

    return tree


def _build_frozen_principals() -> dict[str, dict]:
    """Build principals dict matching the IDs used in _build_frozen_tree."""
    members_25 = [
        {"id": f"member-{i:03d}", "display_name": f"Member {i}", "type": "User", "upn": f"m{i}@contoso.com"}
        for i in range(25)
    ]
    return {
        "user-aaa": {"display_name": "Alice Admin", "type": "User", "upn": "alice@contoso.com", "sub_type": "Member"},
        "user-bbb": {"display_name": "Bob Builder", "type": "User", "upn": "bob@contoso.com", "sub_type": "Member"},
        "user-ccc": {"display_name": "Carol Cloud", "type": "User", "upn": "carol@contoso.com", "sub_type": "Member"},
        "user-ddd": {"display_name": "Dave Dev", "type": "User", "upn": "dave@contoso.com", "sub_type": "Member"},
        "sp-eee": {"display_name": "SP Deploy Bot", "type": "ServicePrincipal", "app_id": "app-eee", "sub_type": "Application"},
        "sp-fff": {"display_name": "SP Infra Agent", "type": "ServicePrincipal", "app_id": "app-fff", "sub_type": "ManagedIdentity", "mi_type": "SystemAssigned"},
        "grp-ggg": {"display_name": "All Engineers", "type": "Group", "sub_type": "Group", "members": members_25},
    }


def _build_frozen_data() -> tuple[dict, dict[str, dict]]:
    """Return (tree, principals) for determinism testing."""
    return _build_frozen_tree(), _build_frozen_principals()


def _serialize(obj) -> str:
    """Deterministic JSON serialization for comparison."""
    return json.dumps(obj, sort_keys=True, default=str)


# ─────────────────────────────────────────────────────────────────────────
# Shuffle helpers — simulate non-deterministic API ordering
# ─────────────────────────────────────────────────────────────────────────

def _deep_shuffle_tree(tree: dict, rng: random.Random) -> dict:
    """Return a deep copy of the tree with lists shuffled at every level."""
    t = copy.deepcopy(tree)
    _shuffle_node(t, rng)
    return t


def _shuffle_node(node: dict, rng: random.Random):
    """Recursively shuffle all list fields in a tree node."""
    if "children" in node and len(node["children"]) > 1:
        rng.shuffle(node["children"])
    if "assignments" in node and len(node["assignments"]) > 1:
        rng.shuffle(node["assignments"])
    if "eligible" in node and len(node["eligible"]) > 1:
        rng.shuffle(node["eligible"])
    for rg in node.get("resource_groups", []):
        if rg.get("assignments") and len(rg["assignments"]) > 1:
            rng.shuffle(rg["assignments"])
        if rg.get("resources") and len(rg["resources"]) > 1:
            rng.shuffle(rg["resources"])
        for res in rg.get("resources", []):
            if res.get("assignments") and len(res["assignments"]) > 1:
                rng.shuffle(res["assignments"])
    if node.get("resource_groups") and len(node["resource_groups"]) > 1:
        rng.shuffle(node["resource_groups"])
    for child in node.get("children", []):
        _shuffle_node(child, rng)


def _shuffle_principals(principals: dict, rng: random.Random) -> dict:
    """Return a copy with group members shuffled."""
    p = copy.deepcopy(principals)
    for info in p.values():
        members = info.get("members")
        if members and len(members) > 1:
            rng.shuffle(members)
    return p


# ─────────────────────────────────────────────────────────────────────────
# Sort helpers — canonical ordering for deterministic comparison
# ─────────────────────────────────────────────────────────────────────────

def _sort_tree_canonical(tree: dict) -> dict:
    """Deep-sort all lists in the tree for canonical comparison."""
    t = copy.deepcopy(tree)
    _sort_node(t)
    return t


def _sort_node(node: dict):
    """Recursively sort children, assignments, eligible, RGs, resources."""
    if "children" in node:
        node["children"].sort(key=lambda c: (c.get("type", ""), c.get("id", "")))
    for key in ("assignments", "eligible"):
        if key in node and node[key]:
            node[key].sort(key=lambda a: (a.get("role_name", ""), a.get("principal_id", ""), a.get("scope", "")))
    for rg in node.get("resource_groups", []):
        if rg.get("assignments"):
            rg["assignments"].sort(key=lambda a: (a.get("role_name", ""), a.get("principal_id", ""), a.get("scope", "")))
        if rg.get("resources"):
            rg["resources"].sort(key=lambda r: r.get("id", ""))
            for res in rg["resources"]:
                if res.get("assignments"):
                    res["assignments"].sort(key=lambda a: (a.get("role_name", ""), a.get("principal_id", ""), a.get("scope", "")))
    if node.get("resource_groups"):
        node["resource_groups"].sort(key=lambda rg: rg.get("name", ""))
    for child in node.get("children", []):
        _sort_node(child)


def _sort_risks_canonical(risks: list[dict]) -> list[dict]:
    """Sort risks with a full deterministic key."""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    r = copy.deepcopy(risks)
    r.sort(key=lambda x: (
        sev_order.get(x.get("severity", "medium"), 9),
        x.get("title", ""),
        x.get("principal_id", ""),
        x.get("scope", ""),
    ))
    return r


def _sort_group_members(principals: dict) -> dict:
    """Sort group members by id for canonical comparison."""
    p = copy.deepcopy(principals)
    for info in p.values():
        members = info.get("members")
        if members:
            members.sort(key=lambda m: m.get("id", ""))
            for m in members:
                sub = m.get("members")
                if sub:
                    sub.sort(key=lambda s: s.get("id", ""))
    return p


# ═════════════════════════════════════════════════════════════════════════
# Test Class: Document determinism gaps
# ═════════════════════════════════════════════════════════════════════════

class TestRbacDeterminismGaps:
    """Tests that document current determinism gaps in the RBAC pipeline.

    Each test runs the same computation with differently-ordered input
    and checks whether the output is identical.
    GAP tests expect differences (the gap exists).
    Once fixes are applied, these tests will be updated to assert equality.
    """

    # ── Gap 1: Tree children ordering ───────────────────────────────

    def test_fix1_tree_children_order_stable_after_sort(self):
        """After _sort_tree_deterministic, all_assignments traversal order
        is identical regardless of original input order."""
        tree, principals = _build_frozen_data()
        rng = random.Random(42)
        shuffled = _deep_shuffle_tree(tree, rng)

        _sort_tree_deterministic(tree)
        _sort_tree_deterministic(shuffled)

        counts_orig = _count_tree(tree)
        counts_shuf = _count_tree(shuffled)

        # Scalar counts match
        for k in ("management_groups", "subscriptions", "resource_groups", "resources",
                   "active", "eligible", "privileged_active", "privileged_eligible"):
            assert counts_orig[k] == counts_shuf[k], f"Mismatch for {k}"

        # After sort, traversal order is identical
        ids_orig = [a["id"] for a in counts_orig["all_assignments"]]
        ids_shuf = [a["id"] for a in counts_shuf["all_assignments"]]
        assert ids_orig == ids_shuf, "all_assignments order must be identical after deterministic sort"

    # ── Gap 2: Subscription ordering in tree ────────────────────────

    def test_fix2_attach_subs_order_stable_after_sort(self):
        """After _sort_tree_deterministic, subscription order is stable
        regardless of dict iteration order during attach."""
        tree = {
            "id": "/providers/Microsoft.Management/managementGroups/root",
            "name": "root",
            "display_name": "Root",
            "type": "ManagementGroup",
            "children": [],
            "assignments": [],
            "eligible": [],
        }
        sub_nodes = {}
        for sid in ["sub-ccc", "sub-aaa", "sub-bbb"]:
            sub_nodes[sid] = {
                "id": f"/subscriptions/{sid}",
                "name": sid,
                "display_name": sid,
                "type": "Subscription",
                "assignments": [],
                "eligible": [],
                "resource_groups": [],
            }
        _attach_subs_to_tree(tree, sub_nodes)
        _sort_tree_deterministic(tree)
        child_names = [c["name"] for c in tree["children"]]

        # Reverse order and attach again
        tree2 = {
            "id": "/providers/Microsoft.Management/managementGroups/root",
            "name": "root",
            "display_name": "Root",
            "type": "ManagementGroup",
            "children": [],
            "assignments": [],
            "eligible": [],
        }
        sub_nodes2 = dict(reversed(list(sub_nodes.items())))
        _attach_subs_to_tree(tree2, sub_nodes2)
        _sort_tree_deterministic(tree2)
        child_names2 = [c["name"] for c in tree2["children"]]

        assert child_names == child_names2, "Subscription order must be identical after sort"

    # ── Gap 3 & 4: Assignment and eligible ordering ─────────────────

    def test_fix3_risk_output_stable_after_tree_sort(self):
        """After sorting tree and using the secondary risk sort key,
        risk output is identical regardless of original assignment order."""
        tree, principals = _build_frozen_data()
        rng = random.Random(99)
        shuffled = _deep_shuffle_tree(tree, rng)

        _sort_tree_deterministic(tree)
        _sort_tree_deterministic(shuffled)

        risks_orig = _compute_risks(tree, principals)
        risks_shuf = _compute_risks(shuffled, principals)

        assert len(risks_orig) == len(risks_shuf)
        assert _serialize(risks_orig) == _serialize(risks_shuf), "Risks must be identical after deterministic sort"

    # ── Gap 5: Resource group ordering ──────────────────────────────

    def test_fix5_rg_order_stable_after_sort(self):
        """After _sort_tree_deterministic, RG order is stable."""
        tree, _ = _build_frozen_data()
        rng = random.Random(77)
        shuffled = _deep_shuffle_tree(tree, rng)

        _sort_tree_deterministic(tree)
        _sort_tree_deterministic(shuffled)

        assert _serialize(tree) == _serialize(shuffled), "Tree serialization must be identical after sort"

    # ── Gap 6: Resource ordering within RGs ─────────────────────────

    def test_fix6_resource_order_stable_after_sort(self):
        """After _sort_tree_deterministic, resource order within RGs is stable."""
        tree, _ = _build_frozen_data()
        # Add extra resource to rg-beta to create a multi-resource RG
        sub1 = [c for c in tree["children"] if c["name"] == "sub-1111"][0]
        rg_beta = [rg for rg in sub1["resource_groups"] if rg["name"] == "rg-beta"][0]
        extra_res = {
            "id": f"{rg_beta['id']}/providers/Microsoft.Compute/virtualMachines/vm-1",
            "name": "vm-1",
            "display_name": "vm-1",
            "resource_type": "Microsoft.Compute/virtualMachines",
            "type": "Resource",
            "location": "eastus",
            "assignments": [],
        }
        rg_beta["resources"].append(extra_res)

        shuffled = copy.deepcopy(tree)
        rng = random.Random(55)
        # Shuffle resources in the copy
        shuf_sub1 = [c for c in shuffled["children"] if c["name"] == "sub-1111"][0]
        shuf_rg_beta = [rg for rg in shuf_sub1["resource_groups"] if rg["name"] == "rg-beta"][0]
        rng.shuffle(shuf_rg_beta["resources"])

        _sort_tree_deterministic(tree)
        _sort_tree_deterministic(shuffled)

        res_ids_orig = [r["id"] for rg in sub1["resource_groups"] for r in rg["resources"]]
        res_ids_shuf = [r["id"] for rg in shuf_sub1["resource_groups"] for r in rg["resources"]]
        assert res_ids_orig == res_ids_shuf, "Resource order must be identical after sort"

    # ── Gap 7: Risk sort has no secondary key ───────────────────────

    def test_fix7_risk_sort_has_secondary_key(self):
        """Risks are now sorted by (severity, title, principal_id, scope)
        so order is stable within the same severity bracket."""
        tree, principals = _build_frozen_data()
        _sort_tree_deterministic(tree)
        risks = _compute_risks(tree, principals)

        by_sev: dict[str, list] = {}
        for r in risks:
            by_sev.setdefault(r["severity"], []).append(r)

        for sev, group in by_sev.items():
            if len(group) < 2:
                continue
            keys = [(r["title"], r["principal_id"], r["scope"]) for r in group]
            sorted_keys = sorted(keys)
            assert keys == sorted_keys, f"Risks within severity '{sev}' must be sorted by (title, principal_id, scope)"

    # ── Gap 8: Group member ordering ────────────────────────────────

    def test_fix8_group_member_order_stable_after_sort(self):
        """After _sort_group_members_deterministic, member order is stable."""
        _, principals = _build_frozen_data()
        rng = random.Random(33)
        shuffled = _shuffle_principals(principals, rng)

        _sort_group_members_deterministic(principals)
        _sort_group_members_deterministic(shuffled)

        ids_orig = [m["id"] for m in principals["grp-ggg"]["members"]]
        ids_shuf = [m["id"] for m in shuffled["grp-ggg"]["members"]]

        assert ids_orig == ids_shuf, "Group member order must be identical after sort"

    # ── Gap 9: principal_sub_types dict key order ───────────────────

    def test_gap9_principal_subtypes_key_order(self):
        """_count_principal_subtypes iterates a set — dict key insertion order
        depends on iteration order of unique_principals set."""
        tree, principals = _build_frozen_data()
        stats1 = _compute_stats(tree, principals)
        st1 = stats1["principal_sub_types"]

        # Run again — set iteration order is fixed within a process,
        # so this won't actually differ in-process. But the JSON key order
        # can differ across runs. Document this gap.
        stats2 = _compute_stats(tree, principals)
        st2 = stats2["principal_sub_types"]

        # Values must always match
        assert st1 == st2
        # But JSON serialization without sort_keys could differ across processes
        j1 = json.dumps(st1, sort_keys=True)
        j2 = json.dumps(st2, sort_keys=True)
        assert j1 == j2, "With sort_keys=True, sub_types must be identical"


# ═════════════════════════════════════════════════════════════════════════
# Test Class: Verify deterministic computations
# ═════════════════════════════════════════════════════════════════════════

class TestRbacComputationDeterminism:
    """Tests verifying that the pure computation functions produce identical
    results when given the exact same input (no shuffling)."""

    def test_stats_identical_across_10_runs(self):
        """_compute_stats returns identical results over 10 runs."""
        tree, principals = _build_frozen_data()
        results = [_compute_stats(copy.deepcopy(tree), principals) for _ in range(10)]
        first = _serialize(results[0])
        for i, r in enumerate(results[1:], 2):
            assert _serialize(r) == first, f"Run {i} stats differ"

    def test_risks_identical_across_10_runs(self):
        """_compute_risks returns identical results over 10 runs with same input."""
        tree, principals = _build_frozen_data()
        results = [_compute_risks(copy.deepcopy(tree), principals) for _ in range(10)]
        first = _serialize(results[0])
        for i, r in enumerate(results[1:], 2):
            assert _serialize(r) == first, f"Run {i} risks differ"

    def test_score_identical_across_10_runs(self):
        """_compute_rbac_score returns identical results over 10 runs."""
        tree, principals = _build_frozen_data()
        stats = _compute_stats(tree, principals)
        risks = _compute_risks(tree, principals)
        scores = [_compute_rbac_score(stats, risks) for _ in range(10)]
        assert len(set(scores)) == 1, f"Scores not identical: {scores}"

    def test_full_pipeline_determinism(self):
        """Combined stats + risks + score must be identical over 10 runs
        given the exact same tree (no shuffling)."""
        tree, principals = _build_frozen_data()
        results = []
        for _ in range(10):
            t = copy.deepcopy(tree)
            p = copy.deepcopy(principals)
            stats = _compute_stats(t, p)
            risks = _compute_risks(t, p)
            score = _compute_rbac_score(stats, risks)
            stats["rbac_score"] = score
            results.append({"stats": stats, "risks": risks})

        first = _serialize(results[0])
        for i, r in enumerate(results[1:], 2):
            assert _serialize(r) == first, f"Run {i} full pipeline differs"

    def test_risk_count_and_severities(self):
        """Validate expected risk counts from our frozen data."""
        tree, principals = _build_frozen_data()
        risks = _compute_risks(tree, principals)

        from collections import Counter
        sevs = Counter(r["severity"] for r in risks)

        # Verify known risks exist
        assert len(risks) > 0
        # Root MG Owner (user-aaa) = critical
        assert sevs.get("critical", 0) >= 1
        # SP with Owner (sp-fff at sub-3333) = high
        assert sevs.get("high", 0) >= 1
        # Large group with Contributor = high
        # Custom role at subscription scope = medium
        assert sevs.get("medium", 0) >= 1

    def test_stats_values_correct(self):
        """Validate expected stats values for our frozen data."""
        tree, principals = _build_frozen_data()
        stats = _compute_stats(tree, principals)

        assert stats["management_groups"] == 2  # root + child-mg-1
        assert stats["subscriptions"] == 3      # sub-1111, sub-2222, sub-3333
        assert stats["resource_groups"] == 3    # rg-alpha, rg-beta, rg-gamma


# ═════════════════════════════════════════════════════════════════════════
# Test Class: Shuffled input → canonical output (post-fix validation)
# ═════════════════════════════════════════════════════════════════════════

class TestRbacShuffledInputCanonical:
    """After fixes, these tests verify that shuffled input still produces
    canonical (sorted) output.

    For now, they document gaps by comparing shuffled output with
    canonically sorted output.
    """

    @pytest.mark.parametrize("seed", [1, 2, 3, 42, 99, 123, 456, 789])
    def test_stats_stable_under_shuffle(self, seed: int):
        """Stats must be identical regardless of input ordering.
        Stats are computed from sums/sets so they should already be stable."""
        tree, principals = _build_frozen_data()
        rng = random.Random(seed)
        shuffled = _deep_shuffle_tree(tree, rng)

        stats_orig = _compute_stats(tree, principals)
        stats_shuf = _compute_stats(shuffled, principals)

        # Remove principal_sub_types for comparison (use sort_keys)
        assert json.dumps(stats_orig, sort_keys=True) == json.dumps(stats_shuf, sort_keys=True)

    @pytest.mark.parametrize("seed", [1, 2, 3, 42, 99, 123])
    def test_risks_stable_under_shuffle_after_canonical_sort(self, seed: int):
        """Risks must be identical after applying canonical sort,
        regardless of input ordering.

        GAP: Currently, risks are only sorted by severity, so within
        the same severity bracket the order can vary. This test applies
        canonical sorting to both sides before comparing."""
        tree, principals = _build_frozen_data()
        rng = random.Random(seed)
        shuffled = _deep_shuffle_tree(tree, rng)

        risks_orig = _sort_risks_canonical(_compute_risks(tree, principals))
        risks_shuf = _sort_risks_canonical(_compute_risks(shuffled, principals))

        assert _serialize(risks_orig) == _serialize(risks_shuf)

    @pytest.mark.parametrize("seed", [1, 42, 99])
    def test_score_stable_under_shuffle(self, seed: int):
        """RBAC score must be identical regardless of tree order."""
        tree, principals = _build_frozen_data()
        rng = random.Random(seed)
        shuffled = _deep_shuffle_tree(tree, rng)

        stats_o = _compute_stats(tree, principals)
        risks_o = _compute_risks(tree, principals)
        score_o = _compute_rbac_score(stats_o, risks_o)

        stats_s = _compute_stats(shuffled, principals)
        risks_s = _compute_risks(shuffled, principals)
        score_s = _compute_rbac_score(stats_s, risks_s)

        assert score_o == score_s

    def test_tree_serialization_identical_after_deterministic_sort(self):
        """After _sort_tree_deterministic, differently ordered trees serialize the same."""
        tree, _ = _build_frozen_data()
        rng = random.Random(42)
        shuffled = _deep_shuffle_tree(tree, rng)

        _sort_tree_deterministic(tree)
        _sort_tree_deterministic(shuffled)

        assert _serialize(tree) == _serialize(shuffled), "Tree must serialize identically after sort"

    def test_tree_serialization_identical_after_canonical_sort(self):
        """After canonical sorting, differently ordered trees serialize the same."""
        tree, _ = _build_frozen_data()
        rng = random.Random(42)
        shuffled = _deep_shuffle_tree(tree, rng)

        sorted_orig = _sort_tree_canonical(tree)
        sorted_shuf = _sort_tree_canonical(shuffled)

        assert _serialize(sorted_orig) == _serialize(sorted_shuf)

    def test_full_pipeline_stable_under_shuffle_with_canonical(self):
        """Full pipeline output (tree + stats + risks + score) is identical
        after canonical sorting, regardless of input ordering."""
        tree, principals = _build_frozen_data()
        rng = random.Random(42)
        shuffled_tree = _deep_shuffle_tree(tree, rng)
        shuffled_principals = _shuffle_principals(principals, rng)

        def _run(t, p):
            t = copy.deepcopy(t)
            p = copy.deepcopy(p)
            stats = _compute_stats(t, p)
            risks = _compute_risks(t, p)
            score = _compute_rbac_score(stats, risks)
            stats["rbac_score"] = score
            return {
                "tree": _sort_tree_canonical(t),
                "principals": _sort_group_members(p),
                "stats": stats,
                "risks": _sort_risks_canonical(risks),
            }

        result_orig = _run(tree, principals)
        result_shuf = _run(shuffled_tree, shuffled_principals)

        assert _serialize(result_orig) == _serialize(result_shuf)
