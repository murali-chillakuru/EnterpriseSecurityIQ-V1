"""RBAC Report orchestrator — coordinates hierarchy collection, principal resolution, and risk analysis."""

from __future__ import annotations

from app.auth import ComplianceCredentials
from app.logger import log
from app.rbac_evaluators.tree_builder import build_mg_tree, attach_subs_to_tree
from app.rbac_evaluators.assignment_collector import collect_mg_assignments, collect_sub_data
from app.rbac_evaluators.principal_resolver import (
    resolve_principals, enrich_principal_subtypes, expand_groups, backfill_principal_types,
)
from app.rbac_evaluators.risks import compute_stats, compute_risks, compute_rbac_score
from app.rbac_evaluators.finding import rbac_finding
from app.rbac_evaluators.enrichment import enrich_compliance_mapping
from app.rbac_evaluators.deterministic import sort_tree_deterministic, sort_group_members_deterministic

# ── Subcategory mapping for risk → finding conversion ────────────────────
_RISK_SUBCATEGORY_MAP: dict[str, str] = {
    "Standing Owner":              "standing_owner_high_scope",
    "Standing User Access Admin":  "standing_owner_high_scope",
    "Standing Contributor at MG":  "contributor_mg_scope",
    "Service Principal with Owner":"sp_with_owner",
    "Large group":                 "large_privileged_group",
    "Custom role":                 "custom_role_high_scope",
    "Service Principal with Contributor": "sp_contributor_broad_scope",
}


def _subcategory_for_risk(title: str) -> str:
    """Map a risk title to a finding subcategory key."""
    for prefix, subcat in _RISK_SUBCATEGORY_MAP.items():
        if title.startswith(prefix):
            return subcat
    # Fallback: snake_case from title
    return title.lower().replace(" ", "_").replace("'", "").replace("(", "").replace(")", "")[:60]


def _risks_to_findings(risks: list[dict]) -> list[dict]:
    """Convert raw risk dicts into standardised finding objects."""
    findings: list[dict] = []
    for r in risks:
        subcat = _subcategory_for_risk(r.get("title", ""))
        remediation_dict: dict = {}
        if r.get("remediation"):
            remediation_dict["Description"] = r["remediation"]
        if r.get("powershell"):
            remediation_dict["PowerShell"] = r["powershell"]
        affected: list[dict] = []
        if r.get("principal_id"):
            affected.append({
                "PrincipalId": r["principal_id"],
                "Scope": r.get("scope", ""),
                "RoleName": r.get("role_name", ""),
            })
        findings.append(rbac_finding(
            category="RBAC",
            subcategory=subcat,
            title=r.get("title", ""),
            description=r.get("detail", ""),
            severity=r.get("severity", "medium"),
            affected_resources=affected,
            remediation=remediation_dict,
        ))
    return findings


async def collect_rbac_data(creds: ComplianceCredentials, subscriptions: list[dict]) -> dict:
    """Build the full RBAC hierarchy with assignments and principal info.

    Returns a dict with keys: tree, principals, stats, risks.
    """
    role_def_cache: dict[str, tuple[str, str]] = {}
    all_principal_ids: set[str] = set()

    log.info("[RbacTree] Phase 1: Building management group hierarchy …")
    tree = await build_mg_tree(creds)

    log.info("[RbacTree] Phase 2: Collecting MG-level role assignments …")
    await collect_mg_assignments(creds, tree, subscriptions, role_def_cache, all_principal_ids)

    log.info("[RbacTree] Phase 3: Collecting subscription data …")
    sub_nodes = await collect_sub_data(creds, subscriptions, role_def_cache, all_principal_ids)

    log.info("[RbacTree] Phase 4: Attaching subscriptions to tree …")
    attach_subs_to_tree(tree, sub_nodes)

    log.info("[RbacTree] Phase 5: Resolving principal display names …")
    principals = await resolve_principals(creds, all_principal_ids)

    backfill_principal_types(tree, principals)

    log.info("[RbacTree] Phase 5b: Enriching principal sub-types …")
    await enrich_principal_subtypes(creds, principals)

    log.info("[RbacTree] Phase 6: Expanding group memberships …")
    await expand_groups(creds, principals)

    log.info("[RbacTree] Sorting tree and principals for deterministic output …")
    sort_tree_deterministic(tree)
    sort_group_members_deterministic(principals)

    log.info("[RbacTree] Phase 7: Computing statistics and risks …")
    stats = compute_stats(tree, principals)
    risks = compute_risks(tree, principals)
    score = compute_rbac_score(stats, risks)
    stats["rbac_score"] = score

    log.info("[RbacTree] Phase 8: Converting risks to findings …")
    findings = _risks_to_findings(risks)
    enrich_compliance_mapping(findings)

    log.info("[RbacTree] Complete — %d assignments, %d principals, %d risks, %d findings, score=%d/100",
             stats["total_assignments"], stats["unique_principals"], len(risks), len(findings), score)

    _tenant_display = ""
    try:
        graph = creds.get_graph_client()
        org_resp = await graph.organization.get()
        orgs = getattr(org_resp, "value", []) or [] if org_resp else []
        if orgs:
            _tenant_display = getattr(orgs[0], "display_name", "") or ""
    except Exception:
        pass

    return {
        "tree": tree, "principals": principals, "stats": stats, "risks": risks,
        "Findings": findings,
        "TenantId": creds.tenant_id,
        "TenantDisplayName": _tenant_display,
    }
