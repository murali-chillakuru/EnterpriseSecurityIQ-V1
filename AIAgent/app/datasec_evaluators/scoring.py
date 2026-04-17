"""
Data Security — Scoring & trend analysis.
"""
from __future__ import annotations

import logging
from app.datasec_evaluators.finding import SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def compute_trend_analysis(
    current_scores: dict,
    current_findings: list[dict],
    previous_result: dict | None = None,
) -> dict:
    """Compare current assessment with a previous assessment to compute trends.

    Returns a trend dict with delta scores, new/resolved findings, and
    direction indicators.  If no previous result is provided, returns
    a baseline-only trend dict.
    """
    trend: dict = {
        "HasBaseline": previous_result is not None,
        "CurrentOverallScore": current_scores.get("OverallScore", 0),
        "ScoreDelta": 0.0,
        "Direction": "baseline",
        "NewFindings": [],
        "ResolvedFindings": [],
        "PersistentFindings": [],
        "CategoryTrends": {},
        "SeverityTrends": {},
    }

    if not previous_result:
        return trend

    prev_scores = previous_result.get("DataSecurityScores", {})
    prev_findings = previous_result.get("Findings", [])

    # Overall score delta
    prev_overall = prev_scores.get("OverallScore", 0)
    curr_overall = current_scores.get("OverallScore", 0)
    trend["PreviousOverallScore"] = prev_overall
    trend["ScoreDelta"] = round(curr_overall - prev_overall, 1)
    if trend["ScoreDelta"] < -2:
        trend["Direction"] = "improving"
    elif trend["ScoreDelta"] > 2:
        trend["Direction"] = "degrading"
    else:
        trend["Direction"] = "stable"

    # Finding-level comparison by subcategory
    prev_subcats = {f.get("Subcategory", ""): f for f in prev_findings}
    curr_subcats = {f.get("Subcategory", ""): f for f in current_findings}

    for subcat, finding in curr_subcats.items():
        if subcat not in prev_subcats:
            trend["NewFindings"].append({
                "Subcategory": subcat,
                "Title": finding.get("Title", ""),
                "Severity": finding.get("Severity", ""),
            })
        else:
            prev_count = prev_subcats[subcat].get("AffectedCount", 0)
            curr_count = finding.get("AffectedCount", 0)
            trend["PersistentFindings"].append({
                "Subcategory": subcat,
                "Title": finding.get("Title", ""),
                "PreviousCount": prev_count,
                "CurrentCount": curr_count,
                "Delta": curr_count - prev_count,
            })

    for subcat, finding in prev_subcats.items():
        if subcat not in curr_subcats:
            trend["ResolvedFindings"].append({
                "Subcategory": subcat,
                "Title": finding.get("Title", ""),
                "Severity": finding.get("Severity", ""),
            })

    # Category score trends
    prev_cat_scores = prev_scores.get("CategoryScores", {})
    curr_cat_scores = current_scores.get("CategoryScores", {})
    all_cats = set(list(prev_cat_scores.keys()) + list(curr_cat_scores.keys()))
    for cat in sorted(all_cats):
        prev_s = prev_cat_scores.get(cat, {}).get("Score", 0)
        curr_s = curr_cat_scores.get(cat, {}).get("Score", 0)
        trend["CategoryTrends"][cat] = {
            "PreviousScore": prev_s,
            "CurrentScore": curr_s,
            "Delta": round(curr_s - prev_s, 1),
        }

    # Severity distribution trends
    prev_sev = prev_scores.get("SeverityDistribution", {})
    curr_sev = current_scores.get("SeverityDistribution", {})
    for sev in ("critical", "high", "medium", "low", "informational"):
        trend["SeverityTrends"][sev] = {
            "Previous": prev_sev.get(sev, 0),
            "Current": curr_sev.get(sev, 0),
            "Delta": curr_sev.get(sev, 0) - prev_sev.get(sev, 0),
        }

    return trend

# ====================================================================
# 6. DATA SECURITY SCORING
# ====================================================================

def compute_data_security_scores(findings: list[dict]) -> dict:
    """Compute composite data-security scores from findings."""
    if not findings:
        return {
            "OverallScore": 0,
            "OverallLevel": "low",
            "CategoryScores": {},
            "SeverityDistribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "TopFindings": [],
        }

    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        sev = f.get("Severity", "medium").lower()
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    cat_findings: dict[str, list[dict]] = {}
    for f in findings:
        cat_findings.setdefault(f.get("Category", "unknown"), []).append(f)

    cat_scores: dict[str, dict] = {}
    for cat, cf in cat_findings.items():
        raw = sum(_SEVERITY_WEIGHTS.get(f.get("Severity", "medium").lower(), 5.0) for f in cf)
        score = min(100.0, raw * 5)
        cat_scores[cat] = {
            "Score": round(score, 1),
            "Level": _ds_score_to_level(score),
            "FindingCount": len(cf),
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
        "OverallLevel": _ds_score_to_level(overall),
        "CategoryScores": cat_scores,
        "SeverityDistribution": severity_dist,
        "TopFindings": [
            {"Title": f.get("Title", ""), "Category": f.get("Category", ""),
             "Severity": f.get("Severity", ""), "AffectedCount": f.get("AffectedCount", 0)}
            for f in sorted_f[:10]
        ],
    }


def _ds_score_to_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


