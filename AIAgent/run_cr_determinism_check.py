#!/usr/bin/env python
"""
Live determinism validation for Copilot Readiness Assessment.

Runs the Copilot readiness assessment 3 times against the same tenant
using identical captured evidence, then compares all outputs for
consistency.

Usage:
  # Full pipeline: collect once, analyse 3×, compare
  python run_cr_determinism_check.py --tenant <tenant-id>

  # Reuse evidence from a prior assessment
  python run_cr_determinism_check.py --tenant <tenant-id> --evidence output/<date>/Copilot-Readiness/captured-evidence.json
"""

from __future__ import annotations

import argparse
import asyncio
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
    analyze_oversharing_risk,
    analyze_label_coverage,
    analyze_dlp_readiness,
    analyze_restricted_search,
    analyze_access_governance,
    analyze_content_lifecycle,
    analyze_audit_monitoring,
    analyze_copilot_security,
    analyze_zero_trust,
    analyze_shadow_ai,
    compute_copilot_readiness_scores,
    _cr_collect,
)
from app.logger import log


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_ANALYZERS = [
    ("oversharing_risk",  analyze_oversharing_risk),
    ("label_coverage",    analyze_label_coverage),
    ("dlp_readiness",     analyze_dlp_readiness),
    ("restricted_search", analyze_restricted_search),
    ("access_governance", analyze_access_governance),
    ("content_lifecycle", analyze_content_lifecycle),
    ("audit_monitoring",  analyze_audit_monitoring),
    ("copilot_security",  analyze_copilot_security),
    ("zero_trust",        analyze_zero_trust),
    ("shadow_ai",         analyze_shadow_ai),
]


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _run_analysis(evidence_index: dict[str, list[dict]], run_label: str) -> dict:
    """Run the full analysis pipeline on evidence and return results."""
    print(f"\n  Running analysis ({run_label}) …")
    all_findings: list[dict] = []
    for name, fn in _ANALYZERS:
        findings = fn(evidence_index)
        all_findings.extend(findings)
        print(f"    {name}: {len(findings)} findings")

    # Deterministic sort (same as engine)
    all_findings.sort(
        key=lambda f: (
            f.get("Category", ""),
            f.get("Subcategory", ""),
            _SEVERITY_ORDER.get(f.get("Severity", "medium").lower(), 9),
        )
    )

    scores = compute_copilot_readiness_scores(all_findings)

    return {
        "RunLabel": run_label,
        "FindingCount": len(all_findings),
        "Findings": all_findings,
        "CopilotReadinessScores": scores,
    }


def _strip_volatile(obj):
    """Recursively strip timestamp and volatile fields for comparison."""
    if isinstance(obj, dict):
        return {
            k: _strip_volatile(v) for k, v in obj.items()
            if k not in ("DetectedAt", "AssessedAt", "RunLabel")
        }
    if isinstance(obj, list):
        return [_strip_volatile(item) for item in obj]
    return obj


def _compare_runs(runs: list[dict], output_dir: str) -> dict:
    """Compare 3 runs and produce a detailed comparison report."""
    report: dict = {
        "ComparedAt": datetime.now(timezone.utc).isoformat(),
        "RunCount": len(runs),
        "Runs": [],
        "FindingIdComparison": {},
        "FieldLevelDiffs": [],
        "ScoreComparison": {},
        "Verdict": "UNKNOWN",
    }

    # ── Run summaries ────────────────────────────────────────────
    for r in runs:
        scores = r.get("CopilotReadinessScores", {})
        report["Runs"].append({
            "Label": r["RunLabel"],
            "FindingCount": r["FindingCount"],
            "OverallScore": scores.get("OverallScore"),
            "ReadinessStatus": scores.get("ReadinessStatus"),
            "SeverityDistribution": scores.get("SeverityDistribution"),
        })

    # ── Finding ID comparison ────────────────────────────────────
    id_sets = [
        set(f["CopilotReadinessFindingId"] for f in r["Findings"])
        for r in runs
    ]
    all_ids_match = id_sets[0] == id_sets[1] == id_sets[2]
    report["FindingIdComparison"] = {
        "AllIdentical": all_ids_match,
        "Run1Count": len(id_sets[0]),
        "Run2Count": len(id_sets[1]),
        "Run3Count": len(id_sets[2]),
        "OnlyInRun1": sorted(id_sets[0] - id_sets[1] - id_sets[2]),
        "OnlyInRun2": sorted(id_sets[1] - id_sets[0] - id_sets[2]),
        "OnlyInRun3": sorted(id_sets[2] - id_sets[0] - id_sets[1]),
    }

    # ── Field-level diff on common findings ──────────────────────
    common_ids = id_sets[0] & id_sets[1] & id_sets[2]
    findings_by_id = []
    for r in runs:
        findings_by_id.append({f["CopilotReadinessFindingId"]: f for f in r["Findings"]})

    skip_keys = {"DetectedAt", "AssessedAt", "RunLabel"}
    diff_count = 0
    for fid in sorted(common_ids):
        f1, f2, f3 = findings_by_id[0][fid], findings_by_id[1][fid], findings_by_id[2][fid]
        all_keys = sorted(set(f1.keys()) | set(f2.keys()) | set(f3.keys()))
        for k in all_keys:
            if k in skip_keys:
                continue
            v1, v2, v3 = f1.get(k), f2.get(k), f3.get(k)
            if v1 != v2 or v1 != v3:
                diff_count += 1
                report["FieldLevelDiffs"].append({
                    "FindingId": fid,
                    "Field": k,
                    "Run1": str(v1)[:200],
                    "Run2": str(v2)[:200],
                    "Run3": str(v3)[:200],
                })

    # ── Score comparison ─────────────────────────────────────────
    scores = [r.get("CopilotReadinessScores", {}) for r in runs]
    overall_scores = [s.get("OverallScore") for s in scores]
    statuses = [s.get("ReadinessStatus") for s in scores]
    sev_dists = [s.get("SeverityDistribution") for s in scores]

    report["ScoreComparison"] = {
        "OverallScoresIdentical": len(set(overall_scores)) == 1,
        "OverallScores": overall_scores,
        "StatusesIdentical": len(set(statuses)) == 1,
        "Statuses": statuses,
        "SeverityDistributionsIdentical": sev_dists[0] == sev_dists[1] == sev_dists[2],
    }

    # ── Full JSON comparison (excluding volatile fields) ─────────
    clean_runs = [_strip_volatile(r) for r in runs]
    json_a = json.dumps(clean_runs[0], sort_keys=True, default=str)
    json_b = json.dumps(clean_runs[1], sort_keys=True, default=str)
    json_c = json.dumps(clean_runs[2], sort_keys=True, default=str)
    full_json_match = (json_a == json_b == json_c)

    # ── Verdict ──────────────────────────────────────────────────
    all_pass = (
        all_ids_match
        and diff_count == 0
        and full_json_match
        and len(set(overall_scores)) == 1
    )
    report["Verdict"] = "PASS ✓ — All 3 runs are deterministic" if all_pass else "FAIL ✗ — Differences detected"
    report["FullJsonMatch"] = full_json_match
    report["FieldLevelDiffCount"] = diff_count

    return report


def _print_comparison(report: dict) -> None:
    """Print comparison results to console."""
    _print_header("DETERMINISM COMPARISON RESULTS")

    # Run summaries
    print("\n  Run Summaries:")
    for r in report["Runs"]:
        print(f"    {r['Label']}: {r['FindingCount']} findings | "
              f"Score={r['OverallScore']} | Status={r['ReadinessStatus']}")
        dist = r.get("SeverityDistribution", {})
        print(f"      Severity: C={dist.get('critical',0)} H={dist.get('high',0)} "
              f"M={dist.get('medium',0)} L={dist.get('low',0)} I={dist.get('informational',0)}")

    # Finding IDs
    print(f"\n  Finding IDs: {'✓ All identical' if report['FindingIdComparison']['AllIdentical'] else '✗ DIFFER'}")
    fic = report["FindingIdComparison"]
    if not fic["AllIdentical"]:
        for key in ("OnlyInRun1", "OnlyInRun2", "OnlyInRun3"):
            ids = fic[key]
            if ids:
                print(f"    {key}: {ids}")

    # Field-level diffs
    print(f"\n  Field-level diffs: {report['FieldLevelDiffCount']}")
    for d in report.get("FieldLevelDiffs", [])[:10]:
        print(f"    {d['FindingId']}.{d['Field']}:")
        print(f"      Run1: {d['Run1'][:100]}")
        print(f"      Run2: {d['Run2'][:100]}")
        print(f"      Run3: {d['Run3'][:100]}")

    # Scores
    sc = report["ScoreComparison"]
    print(f"\n  Scores: {'✓ All identical' if sc['OverallScoresIdentical'] else '✗ DIFFER'} ({sc['OverallScores']})")
    print(f"  Statuses: {'✓ All identical' if sc['StatusesIdentical'] else '✗ DIFFER'} ({sc['Statuses']})")
    print(f"  Severity Distributions: {'✓ All identical' if sc['SeverityDistributionsIdentical'] else '✗ DIFFER'}")
    print(f"  Full JSON Match: {'✓' if report['FullJsonMatch'] else '✗'}")

    # Verdict
    print(f"\n  {'='*60}")
    print(f"  {report['Verdict']}")
    print(f"  {'='*60}")


async def _main(args: argparse.Namespace) -> None:
    _print_header("EnterpriseSecurityIQ — Copilot Readiness Determinism Validation")

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / f"determinism_cr_{ts}"
    os.makedirs(base_dir, exist_ok=True)

    creds = ComplianceCredentials(tenant_id=args.tenant)
    print(f"\n  Tenant: {args.tenant}")

    # ── Step 1: Get evidence ─────────────────────────────────────
    evidence_index: dict[str, list[dict]] = {}

    if args.evidence:
        print(f"  Loading evidence from: {args.evidence}")
        with open(args.evidence, "r", encoding="utf-8") as fh:
            evidence_list = json.load(fh)
        for ev in evidence_list:
            etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
            if etype:
                evidence_index.setdefault(etype, []).append(ev)
        print(f"  Loaded {sum(len(v) for v in evidence_index.values())} evidence records")
    else:
        print("  Collecting evidence from tenant (one-time) …")
        subs = await creds.list_subscriptions()
        evidence_index = await _cr_collect(creds, subs)
        rec_count = sum(len(v) for v in evidence_index.values())
        print(f"  Collected {rec_count} evidence records")

        # Save evidence for reuse
        evidence_flat: list[dict] = []
        for records in evidence_index.values():
            evidence_flat.extend(records)
        evidence_path = base_dir / "captured-evidence.json"
        with open(evidence_path, "w", encoding="utf-8") as fh:
            json.dump(evidence_flat, fh, indent=2, default=str)
        print(f"  Evidence saved: {evidence_path}")

    print(f"\n  Evidence types: {len(evidence_index)}")
    for etype, records in sorted(evidence_index.items()):
        print(f"    {etype}: {len(records)} records")

    # ── Step 2: Run analysis 3 times ─────────────────────────────
    _print_header("RUNNING 3 ANALYSIS PASSES")

    runs: list[dict] = []
    for i in range(1, 4):
        start = time.monotonic()
        result = _run_analysis(evidence_index, f"Run {i}")
        elapsed = time.monotonic() - start
        runs.append(result)
        print(f"  Run {i}: {result['FindingCount']} findings, "
              f"score={result['CopilotReadinessScores']['OverallScore']}, "
              f"{elapsed:.2f}s")

        # Save individual run
        run_dir = base_dir / f"run{i}"
        os.makedirs(run_dir, exist_ok=True)
        run_path = run_dir / "copilot-readiness-assessment.json"
        with open(run_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)

    # ── Step 3: Compare ──────────────────────────────────────────
    _print_header("COMPARING RESULTS")
    report = _compare_runs(runs, str(base_dir))

    # Save comparison report
    report_path = base_dir / "determinism-comparison.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    _print_comparison(report)

    print(f"\n  Output directory: {base_dir}")
    print(f"  Comparison report: {report_path}")

    await creds.close()

    # Exit code based on verdict
    sys.exit(0 if "PASS" in report["Verdict"] else 1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EnterpriseSecurityIQ — Copilot Readiness Determinism Validation",
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to captured-evidence.json from a prior run")
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
