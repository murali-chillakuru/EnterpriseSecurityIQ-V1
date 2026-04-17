"""
Risk scoring — computes composite risk scores from findings.
"""
from __future__ import annotations

from app.risk_evaluators.finding import SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS


def compute_risk_scores(findings: list[dict]) -> dict:
    """Compute composite risk scores from findings."""
    if not findings:
        return {
            "OverallRiskScore": 0,
            "OverallRiskLevel": "low",
            "CategoryScores": {},
            "SeverityDistribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "TopRisks": [],
        }

    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        sev = f.get("Severity", "medium").lower()
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    category_findings: dict[str, list[dict]] = {}
    for f in findings:
        category_findings.setdefault(f.get("Category", "unknown"), []).append(f)

    category_scores: dict[str, dict] = {}
    for cat, cat_f in category_findings.items():
        raw = sum(_SEVERITY_WEIGHTS.get(f.get("Severity", "medium").lower(), 5.0) for f in cat_f)
        score = min(100.0, raw * 5)
        category_scores[cat] = {
            "Score": round(score, 1),
            "Level": _score_to_level(score),
            "FindingCount": len(cat_f),
        }

    total_weight = sum(cs["FindingCount"] for cs in category_scores.values())
    overall = (
        sum(cs["Score"] * cs["FindingCount"] for cs in category_scores.values()) / total_weight
        if total_weight > 0
        else 0
    )

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_WEIGHTS.get(f.get("Severity", "medium").lower(), 5.0),
        reverse=True,
    )

    return {
        "OverallRiskScore": round(overall, 1),
        "OverallRiskLevel": _score_to_level(overall),
        "CategoryScores": category_scores,
        "SeverityDistribution": severity_dist,
        "TopRisks": [
            {"Title": f.get("Title", ""), "Category": f.get("Category", ""),
             "Severity": f.get("Severity", ""), "AffectedCount": f.get("AffectedCount", 0)}
            for f in sorted_findings[:10]
        ],
    }


def _score_to_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
