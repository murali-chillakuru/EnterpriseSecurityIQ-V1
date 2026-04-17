#!/usr/bin/env python
"""
CLI entry-point for Data Security Assessment (Phase 3).

Usage:
  # Standalone — collects lightweight evidence via ARG
  python run_data_security.py --tenant <tenant-id>

  # Reuse evidence from a previous assessment
  python run_data_security.py --tenant <tenant-id> --evidence output/<date>/raw-evidence.json

  # Target specific categories
  python run_data_security.py --tenant <tenant-id> --category storage,encryption

  # Compare with previous run
  python run_data_security.py --tenant <tenant-id> --previous-run output/<date>/Data-Security/data-security-assessment.json

  # Suppress accepted risks
  python run_data_security.py --tenant <tenant-id> --suppressions suppressions.json

  # CI/CD gate mode (exit non-zero if critical/high findings exist)
  python run_data_security.py --tenant <tenant-id> --fail-on-severity high
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
from app.data_security_engine import (
    run_data_security_assessment,
    analyze_storage_exposure,
    analyze_database_security,
    analyze_keyvault_hygiene,
    analyze_encryption_posture,
    analyze_data_classification,
    analyze_cosmosdb_security,
    analyze_postgres_mysql_security,
    analyze_data_access_controls,
    analyze_private_endpoints,
    analyze_purview_security,
    analyze_file_sync_security,
    analyze_m365_dlp,
    analyze_data_classification_security,
    analyze_backup_dr,
    analyze_container_security,
    analyze_network_segmentation,
    analyze_data_residency,
    analyze_threat_detection,
    analyze_sharepoint_governance,
    analyze_redis_security,
    analyze_messaging_security,
    analyze_ai_services_security,
    analyze_data_factory_security,
    analyze_managed_identity_deep,
    analyze_m365_data_lifecycle,
    analyze_dlp_alert_effectiveness,
    analyze_sql_mi_security,
    analyze_app_config_security,
    analyze_cert_lifecycle,
    analyze_databricks_security,
    analyze_apim_security,
    analyze_frontdoor_security,
    analyze_secret_sprawl,
    analyze_firewall_appgw_security,
    analyze_bastion_security,
    analyze_policy_compliance,
    analyze_defender_score,
    analyze_stale_permissions,
    analyze_data_exfiltration,
    analyze_conditional_access_pim,
    analyze_blast_radius,
    analyze_data_flow,
    analyze_config_drift,
    analyze_supply_chain_risk,
    compute_data_security_scores,
)
from app.reports.data_security_report import generate_data_security_report, generate_data_security_excel, generate_executive_brief, generate_cost_methodology_report
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
    print(f"  {badge} {f.get('Title', 'Untitled')}")
    print(f"         Category: {f.get('Category', '')} / {f.get('Subcategory', '')}")
    print(f"         Affected: {f.get('AffectedCount', 0)} resources")
    rem = f.get("Remediation", {})
    if rem.get("Description"):
        print(f"         Fix:      {rem['Description']}")
    print()


def _print_scores(scores: dict) -> None:
    _print_header("DATA SECURITY SCORES")
    level = scores.get("OverallLevel", "unknown").upper()
    score = scores.get("OverallScore", 0)
    print(f"  Overall:  {score}/100 ({level})")

    dist = scores.get("SeverityDistribution", {})
    print(f"  Severity: Critical={dist.get('critical', 0)}  "
          f"High={dist.get('high', 0)}  Medium={dist.get('medium', 0)}  "
          f"Low={dist.get('low', 0)}")

    cats = scores.get("CategoryScores", {})
    if cats:
        print("\n  Category Breakdown:")
        for cat, cs in sorted(cats.items()):
            print(f"    {cat:15s}  {cs.get('Score', 0):5.1f}/100  "
                  f"({cs.get('Level', '').upper()})  "
                  f"{cs.get('FindingCount', 0)} findings")

    top = scores.get("TopFindings", [])
    if top:
        print("\n  Top Findings:")
        for i, t in enumerate(top[:5], 1):
            print(f"    {i}. [{t.get('Severity', '').upper()}] {t.get('Title', '')}")


def _save_results(results: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "data-security-assessment.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    return path


# ── Suppression support ──────────────────────────────────────────────

def _load_suppressions(path: str) -> list[dict]:
    """Load a suppressions.json file.

    Each entry should have at least 'Subcategory' and optionally 'ResourceId'
    plus an 'Reason' for audit.
    """
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

    prev_score = prev.get("DataSecurityScores", {}).get("OverallScore", 0)
    curr_score = current.get("DataSecurityScores", {}).get("OverallScore", 0)

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

def _generate_remediation_scripts(findings: list[dict], output_dir: str, assessed_at: str = "") -> tuple[str, str]:
    """Generate remediate.ps1 and remediate.sh from findings' AzureCLI commands."""
    ts_label = assessed_at or datetime.now(timezone.utc).isoformat()
    os.makedirs(output_dir, exist_ok=True)
    ps_lines: list[str] = [
        "# Auto-generated remediation script (PowerShell)",
        "# Review each command before executing — replace <placeholders> with actual values.",
        "# Generated by EnterpriseSecurityIQ Data Security Assessment",
        f"# Date: {ts_label}",
        "",
    ]
    sh_lines: list[str] = [
        "#!/usr/bin/env bash",
        "# Auto-generated remediation script (Bash)",
        "# Review each command before executing — replace <placeholders> with actual values.",
        "# Generated by EnterpriseSecurityIQ Data Security Assessment",
        f"# Date: {ts_label}",
        "",
    ]

    for f in findings:
        rem = f.get("Remediation", {})
        cli = rem.get("AzureCLI", "")
        if not cli:
            continue
        sev = f.get("Severity", "unknown").upper()
        title = f.get("Title", "Untitled")
        header = f"# [{sev}] {title}"
        ps_lines.append(header)
        sh_lines.append(header)
        for line in cli.strip().split("\n"):
            ps_lines.append(line)
            sh_lines.append(line)
        ps_lines.append("")
        sh_lines.append("")

    ps_path = os.path.join(output_dir, "remediate.ps1")
    sh_path = os.path.join(output_dir, "remediate.sh")
    with open(ps_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(ps_lines))
    with open(sh_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sh_lines))
    return ps_path, sh_path


async def _main(args: argparse.Namespace) -> None:
    import logging as _logging
    if args.verbose:
        _logging.getLogger().setLevel(_logging.DEBUG)
        log.setLevel(_logging.DEBUG)
    quiet = args.quiet

    def _qprint(*a, **kw):
        if not quiet:
            print(*a, **kw)

    def _qprint_header(title):
        if not quiet:
            _print_header(title)

    def _qprint_scores(scores):
        if not quiet:
            _print_scores(scores)

    def _qprint_finding(f):
        if not quiet:
            _print_finding(f)

    _qprint_header("EnterpriseSecurityIQ \u2014 Data Security Assessment")

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

        all_findings: list[dict] = []
        _CAT_MAP = {
            "storage": analyze_storage_exposure,
            "database": analyze_database_security,
            "cosmosdb": analyze_cosmosdb_security,
            "pgmysql": analyze_postgres_mysql_security,
            "keyvault": analyze_keyvault_hygiene,
            "encryption": analyze_encryption_posture,
            "classification": analyze_data_classification,
            "data_access": analyze_data_access_controls,
            "private_endpoints": analyze_private_endpoints,
            "purview": analyze_purview_security,
            "file_sync": analyze_file_sync_security,
            "m365_dlp": analyze_m365_dlp,
            "data_classification": analyze_data_classification_security,
            "backup_dr": analyze_backup_dr,
            "container_security": analyze_container_security,
            "network_segmentation": analyze_network_segmentation,
            "data_residency": analyze_data_residency,
            "threat_detection": analyze_threat_detection,
            "sharepoint_governance": analyze_sharepoint_governance,
            "redis": analyze_redis_security,
            "messaging": analyze_messaging_security,
            "ai_services": analyze_ai_services_security,
            "data_pipeline": analyze_data_factory_security,
            "identity": analyze_managed_identity_deep,
            "m365_data_lifecycle": analyze_m365_data_lifecycle,
            "dlp_alert": analyze_dlp_alert_effectiveness,
            "sql_mi": analyze_sql_mi_security,
            "app_config": analyze_app_config_security,
            "cert_lifecycle": analyze_cert_lifecycle,
            "databricks": analyze_databricks_security,
            "apim": analyze_apim_security,
            "frontdoor": analyze_frontdoor_security,
            "secret_sprawl": analyze_secret_sprawl,
            "firewall": analyze_firewall_appgw_security,
            "bastion": analyze_bastion_security,
            "policy_compliance": analyze_policy_compliance,
            "defender_score": analyze_defender_score,
            "stale_permissions": analyze_stale_permissions,
            "data_exfiltration": analyze_data_exfiltration,
            "conditional_access": analyze_conditional_access_pim,
            "blast_radius": analyze_blast_radius,
            "data_flow": analyze_data_flow,
            "config_drift": analyze_config_drift,
            "supply_chain": analyze_supply_chain_risk,
        }
        for cat in categories:
            fn = _CAT_MAP.get(cat)
            if fn:
                all_findings.extend(fn(evidence_index))

        # Sort findings deterministically
        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        all_findings.sort(
            key=lambda f: (
                f.get("Category", ""),
                f.get("Subcategory", ""),
                _sev_order.get(f.get("Severity", "medium").lower(), 9),
            )
        )
        for _f in all_findings:
            _f.get("AffectedResources", []).sort(
                key=lambda r: r.get("ResourceId", r.get("Name", ""))
            )

        _assessed_at = datetime.now(timezone.utc).isoformat()
        scores = compute_data_security_scores(all_findings)
        results = {
            "AssessmentId": "targeted",
            "AssessedAt": _assessed_at,
            "SubscriptionCount": len(subs),
            "EvidenceSource": "existing_assessment" if evidence else "none",
            "DataSecurityScores": scores,
            "Findings": all_findings,
            "FindingCount": len(all_findings),
        }
    else:
        results = await run_data_security_assessment(creds, evidence=evidence)

    # Apply suppressions
    suppressed_findings: list[dict] = []
    if suppressions:
        active, suppressed_findings = _apply_suppressions(results.get("Findings", []), suppressions)
        results["Findings"] = active
        results["FindingCount"] = len(active)
        results["SuppressedFindings"] = suppressed_findings
        results["SuppressedCount"] = len(suppressed_findings)
        # Recompute scores after suppression
        results["DataSecurityScores"] = compute_data_security_scores(active)
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
            print(f"          New findings: {trend['NewCount']}  |  Resolved: {trend['ResolvedCount']}")

    elapsed = time.monotonic() - start

    _print_scores(results.get("DataSecurityScores", {}))
    for f in results.get("Findings", []):
        _print_finding(f)

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    if args.output_dir:
        out_dir = args.output_dir
    else:
        base_dir = _REPO_ROOT / "output" / ts
        out_dir = str(base_dir / "Data-Security")
    fmts = {f.strip().lower() for f in (args.formats or "json,html,excel,brief,scripts").split(",")}
    json_path = _save_results(results, out_dir) if "json" in fmts else None
    html_path = generate_data_security_report(results, out_dir) if "html" in fmts else None
    excel_path = generate_data_security_excel(results, out_dir) if "excel" in fmts else None
    brief_path = generate_executive_brief(results, out_dir) if "brief" in fmts else None
    cost_path = generate_cost_methodology_report(results, out_dir) if "html" in fmts else None
    ps_path = sh_path = None
    if "scripts" in fmts:
        ps_path, sh_path = _generate_remediation_scripts(
            results.get("Findings", []),
            out_dir,
            assessed_at=results.get("AssessedAt", ""),
        )

    # Generate PDFs from all HTML reports
    pdf_paths = await convert_all_html_to_pdf(out_dir)

    _print_header("COMPLETE")
    print(f"  Findings:  {results.get('FindingCount', 0)}")
    if suppressed_findings:
        print(f"  Suppressed: {len(suppressed_findings)}")
    print(f"  Time:      {elapsed:.1f}s")
    if json_path:  print(f"  JSON:      {json_path}")
    if html_path:  print(f"  Report:    {html_path}")
    if brief_path: print(f"  Brief:     {brief_path}")
    if cost_path:  print(f"  Cost:      {cost_path}")
    if excel_path: print(f"  Excel:     {excel_path}")
    for pp in pdf_paths:
        print(f"  PDF:       {pp}")
    if ps_path:    print(f"  Remediate: {ps_path}")
    if sh_path:    print(f"             {sh_path}")

    await creds.close()

    # CI/CD gate: exit non-zero if findings at or above threshold
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
                print(f"\n  CI/CD GATE FAILED: {len(blocking)} findings at or above '{threshold}' severity")
                sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EnterpriseSecurityIQ — Data Security Assessment",
    )
    parser.add_argument("--tenant", help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to raw-evidence.json from a prior assessment")
    parser.add_argument(
        "--category",
        help="Comma-separated categories to assess (use --list-categories to see all)",
    )
    parser.add_argument(
        "--previous-run",
        help="Path to a previous data-security-assessment.json for trend comparison",
    )
    parser.add_argument(
        "--suppressions",
        help="Path to suppressions.json file to exclude accepted-risk findings",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low", "informational"],
        help="CI/CD gate: exit non-zero if findings at or above this severity exist",
    )
    parser.add_argument(
        "--output-dir",
        help="Custom output directory (default: output/<timestamp>/Data-Security)",
    )
    parser.add_argument(
        "--format",
        dest="formats",
        help="Comma-separated output formats: json,html,excel,brief,scripts (default: all)",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List all available assessment categories and exit",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all console output except final summary line",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging for engine diagnostics",
    )
    args = parser.parse_args()

    if args.list_categories:
        print("Available data-security categories:\n")
        for key in sorted(_CAT_MAP.keys()):
            print(f"  {key}")
        print(f"\nTotal: {len(_CAT_MAP)} categories")
        print("Use --category <name1>,<name2> to assess specific categories.")
        return

    if not args.tenant:
        parser.error("--tenant is required (unless using --list-categories)")

    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
