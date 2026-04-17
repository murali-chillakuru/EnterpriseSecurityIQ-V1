#!/usr/bin/env python
"""
CLI entry-point for Security Risk Gap Analysis (Phase 2).

Usage:
  # Standalone — collects lightweight evidence via ARG + Graph
  python run_risk_analysis.py --tenant <tenant-id>

  # Reuse evidence from a previous assessment
  python run_risk_analysis.py --tenant <tenant-id> --evidence output/<date>/raw-evidence.json

  # Target specific categories
  python run_risk_analysis.py --tenant <tenant-id> --category identity,network
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

# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

from app.auth import ComplianceCredentials
from app.risk_engine import (
    run_risk_analysis,
    analyze_identity_risk,
    analyze_network_risk,
    analyze_config_drift,
    analyze_defender_posture,
    compute_risk_scores,
)
from app.reports.risk_report import generate_risk_report, generate_risk_excel
from app.reports.pdf_export import convert_all_html_to_pdf
from app.logger import log


# ── Formatting helpers ──────────────────────────────────────────────────

_SEV_BADGE = {
    "critical": "\033[91m[CRITICAL]\033[0m",
    "high":     "\033[93m[HIGH]\033[0m",
    "medium":   "\033[33m[MEDIUM]\033[0m",
    "low":      "\033[37m[LOW]\033[0m",
}


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _print_finding(f: dict) -> None:
    sev = f.get("Severity", "medium").lower()
    badge = _SEV_BADGE.get(sev, f"[{sev.upper()}]")
    print(f"  {badge} {f.get('Title', 'Untitled')}")
    print(f"         Category: {f.get('Category', '')} / {f.get('Subcategory', '')}")
    print(f"         Affected: {f.get('AffectedCount', 0)} resources")
    rem = f.get("Remediation", {})
    if rem.get("Description"):
        print(f"         Fix:      {rem['Description']}")
    print()


def _print_scores(scores: dict) -> None:
    _print_header("RISK SCORES")
    level = scores.get("OverallRiskLevel", "unknown").upper()
    score = scores.get("OverallRiskScore", 0)
    print(f"  Overall Risk:  {score}/100 ({level})")

    dist = scores.get("SeverityDistribution", {})
    print(f"  Severity:      Critical={dist.get('critical', 0)}  "
          f"High={dist.get('high', 0)}  Medium={dist.get('medium', 0)}  "
          f"Low={dist.get('low', 0)}")

    cats = scores.get("CategoryScores", {})
    if cats:
        print("\n  Category Breakdown:")
        for cat, cs in cats.items():
            print(f"    {cat:12s}  {cs.get('Score', 0):5.1f}/100  "
                  f"({cs.get('Level', '').upper()})  "
                  f"{cs.get('FindingCount', 0)} findings")

    top = scores.get("TopRisks", [])
    if top:
        print("\n  Top Risks:")
        for i, t in enumerate(top[:5], 1):
            print(f"    {i}. [{t.get('Severity', '').upper()}] {t.get('Title', '')}")


def _save_results(results: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "risk-analysis.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    return path


# ── Main ────────────────────────────────────────────────────────────────

async def _main(args: argparse.Namespace) -> None:
    _print_header("EnterpriseSecurityIQ — Security Risk Gap Analysis")

    creds = ComplianceCredentials(tenant_id=args.tenant)
    print(f"\n  Tenant:  {args.tenant}")

    # Optionally load prior evidence
    evidence: list[dict] | None = None
    if args.evidence:
        print(f"  Evidence: {args.evidence}")
        with open(args.evidence, "r", encoding="utf-8") as fh:
            evidence = json.load(fh)
        print(f"  Loaded {len(evidence):,} evidence records")

    # Category filter
    categories = None
    if args.category:
        categories = [c.strip() for c in args.category.split(",")]
        print(f"  Categories: {', '.join(categories)}")

    start = time.monotonic()

    if categories:
        # Targeted analysis
        from app.auth import list_subscriptions

        subs = await list_subscriptions(creds)
        evidence_index: dict[str, list[dict]] = {}
        if evidence:
            for ev in evidence:
                etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
                if etype:
                    evidence_index.setdefault(etype, []).append(ev)

        all_findings: list[dict] = []
        if "identity" in categories:
            all_findings.extend(analyze_identity_risk(evidence_index))
        if "network" in categories:
            all_findings.extend(analyze_network_risk(evidence_index))
        if "defender" in categories:
            all_findings.extend(await analyze_defender_posture(creds, subs, evidence_index))
        if "config" in categories:
            all_findings.extend(analyze_config_drift(evidence_index))

        scores = compute_risk_scores(all_findings)
        results = {
            "AnalysisId": "targeted",
            "AnalyzedAt": datetime.now(timezone.utc).isoformat(),
            "SubscriptionCount": len(subs),
            "EvidenceSource": "existing_assessment" if evidence else "none",
            "RiskScores": scores,
            "Findings": all_findings,
            "FindingCount": len(all_findings),
        }
    else:
        results = await run_risk_analysis(creds, evidence=evidence)

    elapsed = time.monotonic() - start

    # Display
    _print_scores(results.get("RiskScores", {}))

    for f in results.get("Findings", []):
        _print_finding(f)

    # Save
    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / ts
    out_dir = str(base_dir / "Risk-Analysis")
    json_path = _save_results(results, out_dir)
    html_path = generate_risk_report(results, out_dir)
    excel_path = generate_risk_excel(results, out_dir)

    # Generate PDFs from all HTML reports
    pdf_paths = await convert_all_html_to_pdf(out_dir)

    _print_header("COMPLETE")
    print(f"  Findings:  {results.get('FindingCount', 0)}")
    print(f"  Time:      {elapsed:.1f}s")
    print(f"  JSON:      {json_path}")
    print(f"  Report:    {html_path}")
    print(f"  Excel:     {excel_path}")
    for pp in pdf_paths:
        print(f"  PDF:       {pp}")

    await creds.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EnterpriseSecurityIQ — Security Risk Gap Analysis",
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to raw-evidence.json from a prior assessment")
    parser.add_argument(
        "--category",
        help="Comma-separated categories: identity,network,defender,config",
    )
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
