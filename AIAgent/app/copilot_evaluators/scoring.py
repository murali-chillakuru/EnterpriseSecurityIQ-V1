"""Scoring engine for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _SEVERITY_WEIGHTS


_ALL_CATEGORIES = [
    "oversharing_risk", "label_coverage", "dlp_readiness",
    "restricted_search", "access_governance", "content_lifecycle",
    "audit_monitoring", "copilot_security", "zero_trust", "shadow_ai",
]


def compute_copilot_readiness_scores(findings: list[dict]) -> dict:
    """Compute overall and per-category Copilot readiness scores.

    Readiness score: 100 = fully ready (no gaps), 0 = critical gaps.
    Higher is better.
    """
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    compliance_dist = {"compliant": 0, "gap": 0, "partial": 0}

    if not findings:
        return {
            "OverallScore": 100.0,
            "OverallLevel": "ready",
            "ReadinessStatus": "READY",
            "SeverityDistribution": severity_dist,
            "CategoryScores": {
                cat: {"Score": 100.0, "Level": "ready", "FindingCount": 0, "GapCount": 0}
                for cat in _ALL_CATEGORIES
            },
            "ComplianceBreakdown": compliance_dist,
            "TopFindings": [],
        }

    for f in findings:
        sev = f.get("Severity", "medium").lower()
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
        status = f.get("ComplianceStatus", "gap")
        compliance_dist[status] = compliance_dist.get(status, 0) + 1

    cat_findings: dict[str, list[dict]] = {}
    for f in findings:
        cat_findings.setdefault(f.get("Category", "unknown"), []).append(f)

    cat_scores: dict[str, dict] = {}
    for cat in _ALL_CATEGORIES:
        cf = cat_findings.get(cat, [])
        if not cf:
            cat_scores[cat] = {"Score": 100.0, "Level": "ready", "FindingCount": 0, "GapCount": 0}
            continue
        raw_risk = sum(_SEVERITY_WEIGHTS.get(f.get("Severity", "medium").lower(), 5.0) for f in cf)
        risk = min(100.0, raw_risk * 5)
        readiness = max(0.0, 100.0 - risk)
        cat_scores[cat] = {
            "Score": round(readiness, 1),
            "Level": _readiness_level(readiness),
            "FindingCount": len(cf),
            "GapCount": sum(1 for f in cf if f.get("ComplianceStatus") == "gap"),
        }

    total_w = sum(cs["FindingCount"] for cs in cat_scores.values())
    if total_w > 0:
        overall = sum(cs["Score"] * max(cs["FindingCount"], 1) for cs in cat_scores.values()) / len(_ALL_CATEGORIES)
        overall = sum(cs["Score"] for cs in cat_scores.values()) / len(_ALL_CATEGORIES)
    else:
        overall = 100.0

    sorted_f = sorted(
        findings,
        key=lambda f: _SEVERITY_WEIGHTS.get(f.get("Severity", "medium").lower(), 5.0),
        reverse=True,
    )

    # Readiness status determination (inverted: higher overall = more ready)
    critical_count = severity_dist.get("critical", 0)
    high_count = severity_dist.get("high", 0)
    if critical_count > 0:
        status = "NOT READY"
    elif high_count > 2:
        status = "NOT READY"
    elif high_count > 0:
        status = "NEEDS WORK"
    elif overall < 75:
        status = "NEEDS WORK"
    else:
        status = "READY"

    return {
        "OverallScore": round(overall, 1),
        "OverallLevel": _readiness_level(overall),
        "ReadinessStatus": status,
        "SeverityDistribution": severity_dist,
        "CategoryScores": cat_scores,
        "ComplianceBreakdown": compliance_dist,
        "TopFindings": [
            {"Title": f.get("Title", ""), "Category": f.get("Category", ""),
             "Severity": f.get("Severity", ""), "ComplianceStatus": f.get("ComplianceStatus", ""),
             "AffectedCount": f.get("AffectedCount", 0)}
            for f in sorted_f[:10]
        ],
    }


def _readiness_level(score: float) -> str:
    """Map readiness score to level. Higher score = more ready."""
    if score >= 75:
        return "ready"
    if score >= 50:
        return "mostly_ready"
    if score >= 25:
        return "needs_work"
    return "not_ready"

