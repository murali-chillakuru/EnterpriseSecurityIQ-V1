"""
Remediation Priority Ranking
Ranks non-compliant findings by ROI: risk reduction vs estimated remediation effort.
Produces a prioritised action list for security teams.
"""

from __future__ import annotations
from typing import Any
from app.logger import log


# Effort estimates (hours) by remediation category.
# Lower effort + higher risk → higher priority.
_EFFORT_HOURS: dict[str, float] = {
    # Network / exposure remediations (quick wins)
    "check_nsg_rules":                0.5,
    "check_storage_security":         0.5,
    "check_private_endpoint_adoption": 4.0,
    "check_firewall_protection":      2.0,
    "check_network_segmentation":     3.0,
    "check_webapp_detailed_security":  1.0,
    "check_container_app_network":    2.0,
    "check_apim_network_security":    2.0,
    "check_dns_security":             1.0,
    "check_frontdoor_cdn_security":   1.5,
    "check_aks_advanced_security":    3.0,

    # Identity / access remediations
    "check_mfa_enforcement":          1.0,
    "check_conditional_access":       2.0,
    "check_pim_configuration":        2.0,
    "check_account_management":       1.5,
    "check_workload_identity_security": 2.0,
    "check_auth_methods_security":    1.5,
    "check_managed_identity_hygiene": 1.5,

    # Data protection remediations
    "check_encryption_at_rest":       1.0,
    "check_encryption_in_transit":    1.0,
    "check_key_management":           2.0,
    "check_sql_security":             1.5,
    "check_aks_security":             3.0,
    "check_cosmosdb_advanced_security": 1.5,
    "check_redis_security":           1.0,
    "check_data_analytics_security":  2.0,

    # Governance / monitoring remediations
    "check_diagnostic_settings":      0.5,
    "check_nsg_flow_logs":            0.5,
    "check_policy_compliance":        2.0,
    "check_continuous_monitoring":    3.0,
    "check_sentinel_monitoring":      4.0,
    "check_alert_response_coverage":  2.0,
    "check_defender_posture_advanced": 2.0,
    "check_ai_content_safety":        2.0,
    "check_regulatory_compliance":    4.0,
}

# Default effort for unknown checks
_DEFAULT_EFFORT = 2.0


def _priority_score(risk_score: float, effort_hours: float) -> float:
    """Compute priority score: higher = fix first.

    Priority = risk_score / sqrt(effort_hours)
    Quick fixes with high risk get the highest priority.
    """
    if effort_hours <= 0:
        effort_hours = _DEFAULT_EFFORT
    return round(risk_score / (effort_hours ** 0.5), 2)


def rank_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank non-compliant findings by remediation priority.

    Adds 'Priority', 'PriorityRank', and 'EffortHours' to each finding.
    Returns findings sorted by priority (highest first).
    """
    nc = [f for f in findings if f.get("Status") == "non_compliant"]
    if not nc:
        return findings

    for f in nc:
        check = f.get("EvaluationLogic", "")
        effort = _EFFORT_HOURS.get(check, _DEFAULT_EFFORT)
        risk = f.get("RiskScore", 50)
        priority = _priority_score(risk, effort)
        f["EffortHours"] = effort
        f["Priority"] = priority

    # Sort non-compliant by priority descending
    nc.sort(key=lambda f: f.get("Priority", 0), reverse=True)

    # Assign ranks
    for rank, f in enumerate(nc, 1):
        f["PriorityRank"] = rank
        if rank <= 5:
            f["PriorityLabel"] = "Fix Immediately"
        elif rank <= 15:
            f["PriorityLabel"] = "Fix Soon"
        elif rank <= 30:
            f["PriorityLabel"] = "Plan Fix"
        else:
            f["PriorityLabel"] = "Backlog"

    log.info("Priority ranking: %d findings ranked, top risk score=%.1f, top priority=%.1f",
             len(nc),
             nc[0].get("RiskScore", 0) if nc else 0,
             nc[0].get("Priority", 0) if nc else 0)

    # Rebuild full list maintaining original order for compliant, ranked for nc
    nc_ids = {id(f) for f in nc}
    result = [f for f in findings if id(f) not in nc_ids]
    result.extend(nc)
    return result


def generate_priority_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate priority-ranked summary for reports.

    Returns a dict with:
    - top_10: list of the 10 highest-priority findings
    - by_label: counts per priority label
    - total_effort_hours: estimated total remediation effort
    - quick_wins: findings with effort <= 1h and risk >= 50
    """
    nc = [f for f in findings
          if f.get("Status") == "non_compliant" and f.get("PriorityRank")]
    nc.sort(key=lambda f: f.get("PriorityRank", 9999))

    top_10 = []
    for f in nc[:10]:
        top_10.append({
            "Rank": f.get("PriorityRank"),
            "ControlId": f.get("ControlId", ""),
            "Description": f.get("Description", "")[:150],
            "RiskScore": f.get("RiskScore", 0),
            "EffortHours": f.get("EffortHours", 0),
            "Priority": f.get("Priority", 0),
            "PriorityLabel": f.get("PriorityLabel", ""),
            "Domain": f.get("Domain", ""),
            "ResourceId": f.get("ResourceId", ""),
            "Recommendation": f.get("Recommendation", "")[:200],
        })

    labels = {}
    for f in nc:
        label = f.get("PriorityLabel", "Backlog")
        labels[label] = labels.get(label, 0) + 1

    total_effort = sum(f.get("EffortHours", _DEFAULT_EFFORT) for f in nc)

    quick_wins = [
        {"ControlId": f.get("ControlId", ""), "Description": f.get("Description", "")[:120],
         "RiskScore": f.get("RiskScore", 0), "EffortHours": f.get("EffortHours", 0),
         "ResourceId": f.get("ResourceId", "")}
        for f in nc
        if f.get("EffortHours", 99) <= 1.0 and f.get("RiskScore", 0) >= 50
    ][:10]

    return {
        "Top10": top_10,
        "ByLabel": labels,
        "TotalEffortHours": round(total_effort, 1),
        "QuickWins": quick_wins,
        "TotalRanked": len(nc),
    }
