"""Scoring engine for AI Agent Security assessment."""

from __future__ import annotations

from .finding import _SEVERITY_WEIGHTS


def compute_agent_security_scores(findings: list[dict]) -> dict:
    """Compute overall and per-category AI agent security scores."""
    if not findings:
        return {
            "OverallScore": 0.0,
            "OverallLevel": "secure",
            "SeverityDistribution": {"critical": 0, "high": 0, "medium": 0,
                                      "low": 0, "informational": 0},
            "CategoryScores": {},
            "PlatformBreakdown": {"copilot_studio": 0, "foundry": 0,
                                  "cross-cutting": 0, "entra_identity": 0,
                                  "ai_infra": 0, "agent_orchestration": 0},
            "ComplianceBreakdown": {"compliant": 0, "gap": 0, "partial": 0},
            "TopFindings": [],
        }

    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    platform_dist: dict[str, int] = {}
    compliance_dist = {"compliant": 0, "gap": 0, "partial": 0}

    for f in findings:
        sev = f.get("Severity", "medium").lower()
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
        plat = f.get("Platform", "cross-cutting")
        platform_dist[plat] = platform_dist.get(plat, 0) + 1
        status = f.get("ComplianceStatus", "gap")
        compliance_dist[status] = compliance_dist.get(status, 0) + 1

    cat_findings: dict[str, list[dict]] = {}
    for f in findings:
        cat_findings.setdefault(f.get("Category", "unknown"), []).append(f)

    cat_scores: dict[str, dict] = {}
    for cat, cf in cat_findings.items():
        raw = sum(_SEVERITY_WEIGHTS.get(f.get("Severity", "medium").lower(), 5.0) for f in cf)
        score = min(100.0, raw * 5)
        cat_scores[cat] = {
            "Score": round(score, 1),
            "Level": _security_level(score),
            "FindingCount": len(cf),
            "Platform": cf[0].get("Platform", "cross-cutting") if cf else "",
        }

    total_w = sum(cs["FindingCount"] for cs in cat_scores.values())
    overall = (
        sum(cs["Score"] * cs["FindingCount"] for cs in cat_scores.values()) / total_w
        if total_w > 0 else 0
    )

    sorted_f = sorted(
        findings,
        key=lambda f: _SEVERITY_WEIGHTS.get(f.get("Severity", "medium").lower(), 5.0),
        reverse=True,
    )

    return {
        "OverallScore": round(overall, 1),
        "OverallLevel": _security_level(overall),
        "SeverityDistribution": severity_dist,
        "CategoryScores": cat_scores,
        "PlatformBreakdown": platform_dist,
        "ComplianceBreakdown": compliance_dist,
        "TopFindings": [
            {"Title": f.get("Title", ""), "Category": f.get("Category", ""),
             "Platform": f.get("Platform", ""), "Severity": f.get("Severity", ""),
             "AffectedCount": f.get("AffectedCount", 0)}
            for f in sorted_f[:10]
        ],
    }


def _security_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "secure"

