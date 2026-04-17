#!/usr/bin/env python
"""
Live determinism validation for RBAC Report.

Collects RBAC data from the real tenant once, then re-runs the
computation pipeline (stats, risks, score) 3 times from the same
captured data and compares all outputs for consistency.

Usage:
  python run_rbac_determinism_check.py --tenant <tenant-id>
  python run_rbac_determinism_check.py --tenant <tenant-id> --data output/<ts>/RBAC-Report/rbac-data.json
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

from app.auth import ComplianceCredentials
from app.collectors.azure.rbac_collector import (
    collect_rbac_data,
    _compute_stats,
    _compute_risks,
    _compute_rbac_score,
    _sort_tree_deterministic,
    _sort_group_members_deterministic,
)
from app.logger import log


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _run_computation(data: dict, run_label: str) -> dict:
    """Run stats + risks + score from an already-collected data dict."""
    print(f"\n  Running computation ({run_label}) …")
    tree = copy.deepcopy(data["tree"])
    principals = copy.deepcopy(data["principals"])

    # Apply deterministic sorts (same as collect_rbac_data does)
    _sort_tree_deterministic(tree)
    _sort_group_members_deterministic(principals)

    stats = _compute_stats(tree, principals)
    risks = _compute_risks(tree, principals)
    score = _compute_rbac_score(stats, risks)
    stats["rbac_score"] = score

    print(f"    Assignments: {stats['total_assignments']} | "
          f"Principals: {stats['unique_principals']} | "
          f"Risks: {len(risks)} | Score: {score}/100")

    return {
        "RunLabel": run_label,
        "tree": tree,
        "principals": principals,
        "stats": stats,
        "risks": risks,
    }


def _strip_volatile(obj):
    """Remove volatile fields for comparison."""
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in obj.items()
                if k not in ("RunLabel",)}
    if isinstance(obj, list):
        return [_strip_volatile(item) for item in obj]
    return obj


def _compare_runs(runs: list[dict], output_dir: str) -> dict:
    """Compare 3 runs and produce a detailed comparison report."""
    report: dict = {
        "ComparedAt": datetime.now(timezone.utc).isoformat(),
        "RunCount": len(runs),
        "Runs": [],
        "TreeComparison": {},
        "RiskComparison": {},
        "StatsComparison": {},
        "PrincipalComparison": {},
        "Verdict": "UNKNOWN",
    }

    # ── Run summaries ────────────────────────────────────────────
    for r in runs:
        stats = r["stats"]
        report["Runs"].append({
            "Label": r["RunLabel"],
            "Score": stats.get("rbac_score"),
            "TotalAssignments": stats.get("total_assignments"),
            "UniqueP": stats.get("unique_principals"),
            "RiskCount": len(r["risks"]),
        })

    # ── Tree comparison ──────────────────────────────────────────
    tree_jsons = [json.dumps(r["tree"], sort_keys=True, default=str) for r in runs]
    tree_match = tree_jsons[0] == tree_jsons[1] == tree_jsons[2]
    report["TreeComparison"] = {"AllIdentical": tree_match}

    # ── Risk comparison ──────────────────────────────────────────
    risk_jsons = [json.dumps(r["risks"], sort_keys=True, default=str) for r in runs]
    risk_match = risk_jsons[0] == risk_jsons[1] == risk_jsons[2]
    risk_counts = [len(r["risks"]) for r in runs]
    report["RiskComparison"] = {
        "AllIdentical": risk_match,
        "Counts": risk_counts,
    }

    if not risk_match:
        # Find mismatched risk keys
        r1_keys = set((r["title"], r.get("principal_id",""), r.get("scope","")) for r in runs[0]["risks"])
        r2_keys = set((r["title"], r.get("principal_id",""), r.get("scope","")) for r in runs[1]["risks"])
        r3_keys = set((r["title"], r.get("principal_id",""), r.get("scope","")) for r in runs[2]["risks"])
        report["RiskComparison"]["OnlyInRun1"] = sorted(str(k) for k in r1_keys - r2_keys - r3_keys)
        report["RiskComparison"]["OnlyInRun2"] = sorted(str(k) for k in r2_keys - r1_keys - r3_keys)
        report["RiskComparison"]["OnlyInRun3"] = sorted(str(k) for k in r3_keys - r1_keys - r2_keys)

    # ── Stats comparison ─────────────────────────────────────────
    stat_jsons = [json.dumps(r["stats"], sort_keys=True, default=str) for r in runs]
    stats_match = stat_jsons[0] == stat_jsons[1] == stat_jsons[2]
    scores = [r["stats"].get("rbac_score") for r in runs]
    report["StatsComparison"] = {
        "AllIdentical": stats_match,
        "Scores": scores,
        "ScoresMatch": len(set(scores)) == 1,
    }

    # ── Principal comparison ─────────────────────────────────────
    p_jsons = [json.dumps(r["principals"], sort_keys=True, default=str) for r in runs]
    p_match = p_jsons[0] == p_jsons[1] == p_jsons[2]
    report["PrincipalComparison"] = {"AllIdentical": p_match}

    # ── Full comparison ──────────────────────────────────────────
    clean = [_strip_volatile(r) for r in runs]
    full_jsons = [json.dumps(c, sort_keys=True, default=str) for c in clean]
    full_match = full_jsons[0] == full_jsons[1] == full_jsons[2]

    all_pass = tree_match and risk_match and stats_match and p_match and full_match
    report["FullJsonMatch"] = full_match
    report["Verdict"] = "PASS ✓ — All 3 runs are deterministic" if all_pass else "FAIL ✗ — Differences detected"

    return report


def _print_comparison(report: dict) -> None:
    _print_header("DETERMINISM COMPARISON RESULTS")

    print("\n  Run Summaries:")
    for r in report["Runs"]:
        print(f"    {r['Label']}: {r['TotalAssignments']} assignments | "
              f"{r['UniqueP']} principals | {r['RiskCount']} risks | Score={r['Score']}")

    tc = report["TreeComparison"]
    print(f"\n  Tree:       {'✓ Identical' if tc['AllIdentical'] else '✗ DIFFER'}")

    rc = report["RiskComparison"]
    print(f"  Risks:      {'✓ Identical' if rc['AllIdentical'] else '✗ DIFFER'} (counts: {rc['Counts']})")

    sc = report["StatsComparison"]
    print(f"  Stats:      {'✓ Identical' if sc['AllIdentical'] else '✗ DIFFER'}")
    print(f"  Scores:     {'✓ Identical' if sc['ScoresMatch'] else '✗ DIFFER'} ({sc['Scores']})")

    pc = report["PrincipalComparison"]
    print(f"  Principals: {'✓ Identical' if pc['AllIdentical'] else '✗ DIFFER'}")
    print(f"  Full JSON:  {'✓' if report['FullJsonMatch'] else '✗'}")

    print(f"\n  {'='*60}")
    print(f"  {report['Verdict']}")
    print(f"  {'='*60}")


async def _main(args: argparse.Namespace) -> None:
    _print_header("EnterpriseSecurityIQ — RBAC Report Determinism Validation")

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / f"determinism_rbac_{ts}"
    os.makedirs(base_dir, exist_ok=True)

    data: dict

    if args.data:
        # Reuse captured data
        print(f"\n  Loading data from: {args.data}")
        with open(args.data, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        print(f"  Loaded — {data['stats']['total_assignments']} assignments, "
              f"{len(data.get('risks',[]))} risks")
    else:
        # Collect from tenant
        print(f"\n  Tenant: {args.tenant}")
        print("  Collecting RBAC data from tenant (one-time) …")
        creds = ComplianceCredentials(tenant_id=args.tenant)
        subscriptions = await creds.list_subscriptions()
        data = await collect_rbac_data(creds, subscriptions)

        # Save captured data
        data_path = base_dir / "rbac-data.json"
        with open(data_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True, default=str)
        print(f"  Data saved: {data_path}")

        stats = data["stats"]
        print(f"  Collected: {stats['total_assignments']} assignments, "
              f"{stats['unique_principals']} principals, "
              f"{len(data['risks'])} risks, score={stats['rbac_score']}/100")

        try:
            await creds.credential.close()
        except Exception:
            pass

    # ── Run computation 3 times ──────────────────────────────────
    _print_header("RUNNING 3 COMPUTATION PASSES")

    runs: list[dict] = []
    for i in range(1, 4):
        start = time.monotonic()
        result = _run_computation(data, f"Run {i}")
        elapsed = time.monotonic() - start
        runs.append(result)
        print(f"  Run {i}: {elapsed:.3f}s")

        # Save individual run
        run_dir = base_dir / f"run{i}"
        os.makedirs(run_dir, exist_ok=True)
        with open(run_dir / "rbac-result.json", "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=True, default=str)

    # ── Compare ──────────────────────────────────────────────────
    _print_header("COMPARING RESULTS")
    report = _compare_runs(runs, str(base_dir))

    report_path = base_dir / "determinism-comparison.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    _print_comparison(report)

    print(f"\n  Output directory: {base_dir}")
    print(f"  Comparison report: {report_path}")

    sys.exit(0 if "PASS" in report["Verdict"] else 1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EnterpriseSecurityIQ — RBAC Report Determinism Validation",
    )
    parser.add_argument("--tenant", "-t", default="", help="Azure AD tenant ID")
    parser.add_argument("--data", "-d", default="", help="Path to rbac-data.json from a prior run")
    args = parser.parse_args()

    if not args.tenant and not args.data:
        parser.error("Either --tenant or --data is required")

    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
