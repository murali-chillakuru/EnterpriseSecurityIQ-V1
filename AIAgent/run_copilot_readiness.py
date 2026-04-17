#!/usr/bin/env python
"""
CLI entry-point for M365 Copilot Readiness Assessment.

Usage:
  # Full assessment
  python run_copilot_readiness.py --tenant <tenant-id>

  # Reuse evidence from a prior assessment
  python run_copilot_readiness.py --tenant <tenant-id> --evidence output/<date>/raw-evidence.json

  # Target specific categories
  python run_copilot_readiness.py --tenant <tenant-id> --category oversharing,labels

  # Compare with previous run
  python run_copilot_readiness.py --tenant <tenant-id> --previous-run output/<date>/Copilot-Readiness/copilot-readiness-assessment.json

  # Suppress accepted risks
  python run_copilot_readiness.py --tenant <tenant-id> --suppressions suppressions.json

  # CI/CD gate
  python run_copilot_readiness.py --tenant <tenant-id> --fail-on-severity high
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

from app.auth import ComplianceCredentials
from app.copilot_readiness_engine import (
    run_copilot_readiness_assessment,
    analyze_oversharing_risk,
    analyze_label_coverage,
    analyze_dlp_readiness,
    analyze_restricted_search,
    analyze_access_governance,
    analyze_content_lifecycle,
    analyze_audit_monitoring,
    analyze_zero_trust,
    analyze_shadow_ai,
    compute_copilot_readiness_scores,
    _cr_collect,
)
from app.reports.copilot_readiness_report import generate_copilot_readiness_report
from app.reports.pdf_export import convert_all_html_to_pdf
from app.logger import log

_SEV_BADGE = {
    "critical": "\033[91m[CRITICAL]\033[0m",
    "high":     "\033[93m[HIGH]\033[0m",
    "medium":   "\033[33m[MEDIUM]\033[0m",
    "low":      "\033[37m[LOW]\033[0m",
    "informational": "\033[90m[INFO]\033[0m",
}


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _print_finding(f: dict) -> None:
    sev = f.get("Severity", "medium").lower()
    badge = _SEV_BADGE.get(sev, f"[{sev.upper()}]")
    status = f.get("ComplianceStatus", "gap").upper()
    print(f"  {badge} [{status}] {f.get('Title', 'Untitled')}")
    print(f"         Category: {f.get('Category', '')} / {f.get('Subcategory', '')}")
    print(f"         Affected: {f.get('AffectedCount', 0)} resources")
    rem = f.get("Remediation", {})
    if rem.get("Description"):
        print(f"         Fix:      {rem['Description']}")
    print()


def _print_scores(scores: dict) -> None:
    _print_header("COPILOT READINESS SCORES")
    status = scores.get("ReadinessStatus", "UNKNOWN")
    score = scores.get("OverallScore", 0)
    print(f"  Overall:  {score}/100 ({status})")

    dist = scores.get("SeverityDistribution", {})
    print(f"  Severity: Critical={dist.get('critical', 0)}  "
          f"High={dist.get('high', 0)}  Medium={dist.get('medium', 0)}  "
          f"Low={dist.get('low', 0)}  Informational={dist.get('informational', 0)}")

    compliance = scores.get("ComplianceBreakdown", {})
    print(f"  Status:   Compliant={compliance.get('compliant', 0)}  "
          f"Gap={compliance.get('gap', 0)}  Partial={compliance.get('partial', 0)}")

    cats = scores.get("CategoryScores", {})
    if cats:
        print("\n  Category Breakdown:")
        for cat, cs in cats.items():
            print(f"    {cat:25s}  {cs.get('Score', 0):5.1f}/100  "
                  f"({cs.get('Level', '').upper()})  "
                  f"{cs.get('FindingCount', 0)} gaps")


def _print_collection_warnings(results: dict) -> None:
    """Surface collection warnings from the assessment results."""
    findings = results.get("Findings", [])
    warnings = [f for f in findings if f.get("Subcategory") in ("unable_to_assess", "partial_site_discovery")]
    categories = results.get("Categories", {})
    for cat_findings in categories.values():
        for f in (cat_findings if isinstance(cat_findings, list) else []):
            if f.get("Subcategory") in ("unable_to_assess", "partial_site_discovery") and f not in warnings:
                warnings.append(f)
    if warnings:
        _print_header("COLLECTION WARNINGS")
        for w in warnings:
            print(f"  \033[93m(!)\033[0m {w.get('Title', '')}")
            rem = w.get("Remediation", {})
            if rem.get("Description"):
                print(f"       Fix: {rem['Description']}")
        print()


def _save_results(results: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "copilot-readiness-assessment.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    return path


def _export_findings_csv(findings: list[dict], output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "copilot-readiness-findings.csv")
    fieldnames = [
        "Severity", "ComplianceStatus", "Category", "Subcategory",
        "Title", "AffectedCount", "Description", "Remediation",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            rem = f.get("Remediation", {})
            writer.writerow({
                "Severity": f.get("Severity", ""),
                "ComplianceStatus": f.get("ComplianceStatus", ""),
                "Category": f.get("Category", ""),
                "Subcategory": f.get("Subcategory", ""),
                "Title": f.get("Title", ""),
                "AffectedCount": f.get("AffectedCount", 0),
                "Description": f.get("Description", ""),
                "Remediation": rem.get("Description", ""),
            })
    return csv_path


# ── Suppression support ──────────────────────────────────────────────

def _load_suppressions(path: str) -> list[dict]:
    """Load a suppressions.json file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, list) else data.get("suppressions", [])


def _apply_suppressions(findings: list[dict], suppressions: list[dict]) -> tuple[list[dict], list[dict]]:
    """Filter out suppressed findings.  Returns (active, suppressed)."""
    if not suppressions:
        return findings, []
    suppress_set: set[tuple[str, str]] = set()
    suppress_subcat: set[str] = set()
    for s in suppressions:
        subcat = s.get("Subcategory", s.get("subcategory", ""))
        rid = s.get("ResourceId", s.get("resource_id", ""))
        if subcat and rid:
            suppress_set.add((subcat.lower(), rid.lower()))
        elif subcat:
            suppress_subcat.add(subcat.lower())
    active: list[dict] = []
    suppressed: list[dict] = []
    for f in findings:
        subcat = (f.get("Subcategory", "") or "").lower()
        resources = f.get("AffectedResources", [])
        if subcat in suppress_subcat:
            suppressed.append(f)
        elif resources and all(
            (subcat, (r.get("ResourceId", "") or "").lower()) in suppress_set
            for r in resources if r.get("ResourceId")
        ):
            suppressed.append(f)
        else:
            active.append(f)
    return active, suppressed


# ── Trend comparison ─────────────────────────────────────────────────

def _compute_trend(current: dict, previous_path: str) -> dict | None:
    """Compare current results against a previous run's JSON."""
    try:
        with open(previous_path, "r", encoding="utf-8") as fh:
            prev = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Could not load previous run: %s", exc)
        return None

    prev_findings = prev.get("Findings", [])
    curr_findings = current.get("Findings", [])

    prev_keys = {(f.get("Category", ""), f.get("Subcategory", "")) for f in prev_findings}
    curr_keys = {(f.get("Category", ""), f.get("Subcategory", "")) for f in curr_findings}

    new_keys = curr_keys - prev_keys
    resolved_keys = prev_keys - curr_keys

    prev_score = prev.get("CopilotReadinessScores", {}).get("OverallScore", 0)
    curr_score = current.get("CopilotReadinessScores", {}).get("OverallScore", 0)

    return {
        "PreviousAssessedAt": prev.get("AssessedAt", ""),
        "PreviousScore": prev_score,
        "CurrentScore": curr_score,
        "ScoreDelta": round(curr_score - prev_score, 1),
        "NewFindings": [f for f in curr_findings if (f.get("Category", ""), f.get("Subcategory", "")) in new_keys],
        "ResolvedFindings": [f for f in prev_findings if (f.get("Category", ""), f.get("Subcategory", "")) in resolved_keys],
        "NewCount": len(new_keys),
        "ResolvedCount": len(resolved_keys),
        "PreviousFindingCount": len(prev_findings),
        "CurrentFindingCount": len(curr_findings),
    }


# ── Auto-remediation scripts ────────────────────────────────────────

def _generate_remediation_scripts(findings: list[dict], output_dir: str) -> tuple[str, str]:
    """Generate remediate.ps1 and remediate.sh from findings."""
    os.makedirs(output_dir, exist_ok=True)
    ps_lines: list[str] = [
        "# Auto-generated Copilot Readiness remediation script (PowerShell)",
        "# Review each command before executing — replace <placeholders> with actual values.",
        f"# Date: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    sh_lines: list[str] = [
        "#!/usr/bin/env bash",
        "# Auto-generated Copilot Readiness remediation script (Bash)",
        "# Review each command before executing — replace <placeholders> with actual values.",
        f"# Date: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]

    for f in findings:
        rem = f.get("Remediation", {})
        cli = rem.get("AzureCLI", "")
        ps = rem.get("PowerShell", "")
        if not cli and not ps:
            continue
        sev = f.get("Severity", "unknown").upper()
        title = f.get("Title", "Untitled")
        header = f"# [{sev}] {title}"
        if ps:
            ps_lines.append(header)
            for line in ps.strip().split("\n"):
                ps_lines.append(line)
            ps_lines.append("")
        if cli:
            sh_lines.append(header)
            for line in cli.strip().split("\n"):
                sh_lines.append(line)
            sh_lines.append("")

    ps_path = os.path.join(output_dir, "remediate.ps1")
    sh_path = os.path.join(output_dir, "remediate.sh")
    with open(ps_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(ps_lines))
    with open(sh_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sh_lines))
    return ps_path, sh_path


async def _main(args: argparse.Namespace) -> None:
    _print_header("EnterpriseSecurityIQ — M365 Copilot Readiness Assessment")

    creds = ComplianceCredentials(tenant_id=args.tenant)
    print(f"\n  Tenant:  {args.tenant}")

    evidence: list[dict] | None = None
    if args.evidence:
        print(f"  Evidence: {args.evidence}")
        with open(args.evidence, "r", encoding="utf-8") as fh:
            evidence = json.load(fh)
        print(f"  Loaded {len(evidence):,} evidence records")

    categories = None
    if args.category:
        categories = [c.strip() for c in args.category.split(",")]
        print(f"  Categories: {', '.join(categories)}")

    # Load suppressions if provided
    suppressions: list[dict] = []
    if args.suppressions:
        print(f"  Suppressions: {args.suppressions}")
        suppressions = _load_suppressions(args.suppressions)
        print(f"  Loaded {len(suppressions)} suppression rules")

    start = time.monotonic()

    if categories:
        subs = await creds.list_subscriptions()
        evidence_index: dict[str, list[dict]] = {}
        if evidence:
            for ev in evidence:
                etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
                if etype:
                    evidence_index.setdefault(etype, []).append(ev)

        _CAT_MAP = {
            "oversharing": analyze_oversharing_risk,
            "oversharing_risk": analyze_oversharing_risk,
            "labels": analyze_label_coverage,
            "label_coverage": analyze_label_coverage,
            "dlp": analyze_dlp_readiness,
            "dlp_readiness": analyze_dlp_readiness,
            "restricted_search": analyze_restricted_search,
            "access": analyze_access_governance,
            "access_governance": analyze_access_governance,
            "lifecycle": analyze_content_lifecycle,
            "content_lifecycle": analyze_content_lifecycle,
            "audit": analyze_audit_monitoring,
            "audit_monitoring": analyze_audit_monitoring,
        }

        # E5: Validate category names
        invalid_cats = [c for c in categories if c not in _CAT_MAP]
        if invalid_cats:
            print(f"\n  ERROR: Unknown categories: {', '.join(invalid_cats)}")
            print(f"  Valid values: {', '.join(sorted(set(_CAT_MAP.keys())))}")
            await creds.close()
            sys.exit(2)

        # E1: Collect evidence when --category is used without --evidence
        if not evidence_index:
            log.info("No evidence provided — running targeted collection for selected categories")
            print("\n  Collecting evidence for selected categories …")
            evidence_index = await _cr_collect(creds, subs)

        all_findings: list[dict] = []
        for cat in categories:
            fn = _CAT_MAP.get(cat)
            if fn:
                all_findings.extend(fn(evidence_index))

        scores = compute_copilot_readiness_scores(all_findings)
        results = {
            "AssessmentId": "targeted",
            "AssessedAt": datetime.now(timezone.utc).isoformat(),
            "SubscriptionCount": len(subs),
            "EvidenceSource": "existing_assessment" if evidence else "none",
            "CopilotReadinessScores": scores,
            "Findings": all_findings,
            "FindingCount": len(all_findings),
        }
    else:
        results = await run_copilot_readiness_assessment(creds, evidence=evidence)

    # Apply suppressions
    suppressed_findings: list[dict] = []
    if suppressions:
        active, suppressed_findings = _apply_suppressions(results.get("Findings", []), suppressions)
        results["Findings"] = active
        results["FindingCount"] = len(active)
        results["SuppressedFindings"] = suppressed_findings
        results["SuppressedCount"] = len(suppressed_findings)
        results["CopilotReadinessScores"] = compute_copilot_readiness_scores(active)
        print(f"\n  Suppressed {len(suppressed_findings)} findings (accepted risk)")

    # Trend comparison
    trend: dict | None = None
    if args.previous_run:
        trend = _compute_trend(results, args.previous_run)
        if trend:
            results["Trend"] = trend
            delta = trend["ScoreDelta"]
            arrow = "↑" if delta > 0 else "↓" if delta < 0 else "→"
            print(f"\n  Trend:  {trend['PreviousScore']}/100 → {trend['CurrentScore']}/100 ({arrow}{abs(delta)})")
            print(f"          New gaps: {trend['NewCount']}  |  Resolved: {trend['ResolvedCount']}")

    elapsed = time.monotonic() - start

    # E2: Surface collection warnings in console
    _print_collection_warnings(results)

    _print_scores(results.get("CopilotReadinessScores", {}))
    for f in results.get("Findings", []):
        _print_finding(f)

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / ts
    out_dir = str(base_dir / "Copilot-Readiness")
    json_path = _save_results(results, out_dir)
    html_path = generate_copilot_readiness_report(results, out_dir)
    excel_path = pathlib.Path(out_dir) / "copilot-readiness-assessment.xlsx"
    csv_path = _export_findings_csv(results.get("Findings", []), out_dir)
    ps_path, sh_path = _generate_remediation_scripts(results.get("Findings", []), out_dir)

    # Generate PDFs from all HTML reports
    pdf_paths = await convert_all_html_to_pdf(out_dir)

    _print_header("COMPLETE")
    print(f"  Gaps:      {results.get('FindingCount', 0)}")
    if suppressed_findings:
        print(f"  Suppressed: {len(suppressed_findings)}")
    print(f"  Status:    {results.get('CopilotReadinessScores', {}).get('ReadinessStatus', 'UNKNOWN')}")
    print(f"  Time:      {elapsed:.1f}s")
    print(f"  JSON:      {json_path}")
    print(f"  Report:    {html_path}")
    if excel_path.exists():
        print(f"  Excel:     {excel_path}")
    print(f"  CSV:       {csv_path}")
    for pp in pdf_paths:
        print(f"  PDF:       {pp}")
    print(f"  Remediate: {ps_path}")
    print(f"             {sh_path}")

    await creds.close()

    if args.fail_on_severity:
        sev_order = ["informational", "low", "medium", "high", "critical"]
        threshold = args.fail_on_severity.lower()
        if threshold in sev_order:
            threshold_idx = sev_order.index(threshold)
            blocking = [
                f for f in results.get("Findings", [])
                if sev_order.index(f.get("Severity", "informational").lower()) >= threshold_idx
            ]
            if blocking:
                print(f"\n  CI/CD GATE FAILED: {len(blocking)} gaps at or above '{threshold}' severity")
                sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EnterpriseSecurityIQ — M365 Copilot Readiness Assessment",
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to raw-evidence.json from a prior assessment")
    parser.add_argument(
        "--category",
        help="Comma-separated categories: oversharing,labels,dlp,restricted_search,access,lifecycle,audit",
    )
    parser.add_argument(
        "--previous-run",
        help="Path to a previous copilot-readiness-assessment.json for trend comparison",
    )
    parser.add_argument(
        "--suppressions",
        help="Path to suppressions.json file to exclude accepted-risk findings",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low", "informational"],
        help="CI/CD gate: exit non-zero if gaps at or above this severity exist",
    )
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
