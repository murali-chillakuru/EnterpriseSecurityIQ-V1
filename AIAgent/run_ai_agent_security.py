#!/usr/bin/env python
"""
CLI entry-point for AI Agent Security Assessment.

Usage:
  # Full assessment
  python run_ai_agent_security.py --tenant <tenant-id>

  # Reuse evidence from a prior assessment
  python run_ai_agent_security.py --tenant <tenant-id> --evidence output/<date>/raw-evidence.json

  # Target specific categories
  python run_ai_agent_security.py --tenant <tenant-id> --category cs_authentication,foundry_network

  # Compare with previous run
  python run_ai_agent_security.py --tenant <tenant-id> --previous-run output/<date>/AI-Agent-Security/ai-agent-security-assessment.json

  # Suppress accepted risks
  python run_ai_agent_security.py --tenant <tenant-id> --suppressions suppressions.json

  # CI/CD gate
  python run_ai_agent_security.py --tenant <tenant-id> --fail-on-severity high
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
from app.ai_agent_security_engine import (
    run_ai_agent_security_assessment,
    analyze_cs_authentication,
    analyze_cs_data_connectors,
    analyze_cs_logging,
    analyze_cs_channels,
    analyze_cs_knowledge_sources,
    analyze_cs_generative_ai,
    analyze_cs_governance,
    analyze_cs_connector_security,
    analyze_foundry_network,
    analyze_foundry_identity,
    analyze_foundry_content_safety,
    analyze_foundry_deployments,
    analyze_foundry_governance,
    analyze_foundry_compute,
    analyze_foundry_datastores,
    analyze_foundry_endpoints,
    analyze_foundry_registry,
    analyze_foundry_connections,
    analyze_foundry_serverless,
    analyze_foundry_ws_diagnostics,
    analyze_foundry_prompt_shields,
    analyze_foundry_model_catalog,
    analyze_foundry_data_exfiltration,
    analyze_custom_api_security,
    analyze_custom_data_residency,
    analyze_custom_content_leakage,
    analyze_entra_ai_service_principals,
    analyze_entra_ai_conditional_access,
    analyze_entra_ai_consent,
    analyze_ai_diagnostics,
    analyze_ai_model_governance,
    analyze_ai_threat_protection,
    analyze_ai_data_governance,
    analyze_ai_defender_coverage,
    analyze_ai_policy_compliance,
    analyze_agent_communication,
    analyze_agent_governance,
    compute_agent_security_scores,
)
from app.reports.ai_agent_security_report import generate_ai_agent_security_report, generate_ai_agent_security_excel
from app.reports.pdf_export import convert_all_html_to_pdf
from app.logger import log

_SEV_BADGE = {
    "critical": "\033[91m[CRITICAL]\033[0m",
    "high":     "\033[93m[HIGH]\033[0m",
    "medium":   "\033[33m[MEDIUM]\033[0m",
    "low":      "\033[37m[LOW]\033[0m",
    "informational": "\033[90m[INFO]\033[0m",
}

_PLATFORM_ICON = {
    "copilot_studio": "[CS]",
    "foundry": "[FND]",
    "cross-cutting": "[CUS]",
    "entra_identity": "[ENT]",
    "ai_infra": "[AIF]",
    "agent_orchestration": "[AGT]",
}


def _print_header(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")


def _print_finding(f: dict) -> None:
    sev = f.get("Severity", "medium").lower()
    badge = _SEV_BADGE.get(sev, f"[{sev.upper()}]")
    platform = f.get("Platform", "cross-cutting")
    plat_icon = _PLATFORM_ICON.get(platform, "")
    print(f"  {badge} {plat_icon} {f.get('Title', 'Untitled')}")
    print(f"         Category: {f.get('Category', '')} / {f.get('Subcategory', '')}")
    print(f"         Platform: {platform}")
    print(f"         Affected: {f.get('AffectedCount', 0)} resources")
    rem = f.get("Remediation", {})
    if rem.get("Description"):
        print(f"         Fix:      {rem['Description']}")
    print()


def _print_scores(scores: dict) -> None:
    _print_header("AI AGENT SECURITY SCORES")
    level = scores.get("OverallLevel", "unknown").upper()
    score = scores.get("OverallScore", 0)
    print(f"  Overall:  {score}/100 ({level})")

    dist = scores.get("SeverityDistribution", {})
    print(f"  Severity: Critical={dist.get('critical', 0)}  "
          f"High={dist.get('high', 0)}  Medium={dist.get('medium', 0)}  "
          f"Low={dist.get('low', 0)}")

    plat = scores.get("PlatformBreakdown", {})
    print(f"  Platforms: Copilot Studio={plat.get('copilot_studio', 0)}  "
          f"Foundry={plat.get('foundry', 0)}  Cross-cutting={plat.get('cross-cutting', 0)}")

    cats = scores.get("CategoryScores", {})
    if cats:
        print("\n  Category Breakdown:")
        for cat, cs in cats.items():
            print(f"    {cat:30s}  {cs.get('Score', 0):5.1f}/100  "
                  f"({cs.get('Level', '').upper()})  "
                  f"{cs.get('FindingCount', 0)} findings")


def _save_results(results: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "ai-agent-security-assessment.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    return path


def _export_findings_csv(findings: list[dict], output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "ai-agent-security-findings.csv")
    fieldnames = [
        "Severity", "Platform", "Category", "Subcategory",
        "Title", "AffectedCount", "Description", "Remediation", "AzureCLI",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            rem = f.get("Remediation", {})
            writer.writerow({
                "Severity": f.get("Severity", ""),
                "Platform": f.get("Platform", ""),
                "Category": f.get("Category", ""),
                "Subcategory": f.get("Subcategory", ""),
                "Title": f.get("Title", ""),
                "AffectedCount": f.get("AffectedCount", 0),
                "Description": f.get("Description", ""),
                "Remediation": rem.get("Description", ""),
                "AzureCLI": rem.get("AzureCLI", ""),
            })
    return csv_path


def _generate_remediation_scripts(findings: list[dict], output_dir: str) -> tuple[str, str]:
    """Generate remediate.ps1 and remediate.sh from findings' AzureCLI/PowerShell commands."""
    os.makedirs(output_dir, exist_ok=True)
    header_ps = [
        "# Auto-generated AI agent security remediation script (PowerShell)",
        "# Review each command before executing.",
        f"# Date: {datetime.now(timezone.utc).isoformat()}", "",
    ]
    header_sh = [
        "#!/usr/bin/env bash",
        "# Auto-generated AI agent security remediation script (Bash)",
        "# Review each command before executing.",
        f"# Date: {datetime.now(timezone.utc).isoformat()}", "",
    ]
    for f in findings:
        rem = f.get("Remediation", {})
        cli = rem.get("AzureCLI", "")
        ps = rem.get("PowerShell", "")
        if not cli and not ps:
            continue
        line = f"# [{f.get('Severity', '').upper()}] {f.get('Title', '')}"
        if ps:
            header_ps.append(line)
            for cmd in ps.strip().split("\n"):
                header_ps.append(cmd)
            header_ps.append("")
        if cli:
            header_sh.append(line)
            for cmd in cli.strip().split("\n"):
                header_sh.append(cmd)
            header_sh.append("")

    ps_path = os.path.join(output_dir, "remediate.ps1")
    sh_path = os.path.join(output_dir, "remediate.sh")
    with open(ps_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(header_ps))
    with open(sh_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(header_sh))
    return ps_path, sh_path


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

    prev_score = prev.get("AgentSecurityScores", {}).get("OverallScore", 0)
    curr_score = current.get("AgentSecurityScores", {}).get("OverallScore", 0)

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


async def _main(args: argparse.Namespace) -> None:
    _print_header("EnterpriseSecurityIQ — AI Agent Security Assessment")

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
            # A – Copilot Studio
            "cs_authentication": analyze_cs_authentication,
            "cs_data_connectors": analyze_cs_data_connectors,
            "cs_logging": analyze_cs_logging,
            "cs_channels": analyze_cs_channels,
            "cs_knowledge_sources": analyze_cs_knowledge_sources,
            "cs_generative_ai": analyze_cs_generative_ai,
            "cs_governance": analyze_cs_governance,
            "cs_connector_security": analyze_cs_connector_security,
            # B – Foundry / AI Foundry
            "foundry_network": analyze_foundry_network,
            "foundry_identity": analyze_foundry_identity,
            "foundry_content_safety": analyze_foundry_content_safety,
            "foundry_deployments": analyze_foundry_deployments,
            "foundry_governance": analyze_foundry_governance,
            "foundry_compute": analyze_foundry_compute,
            "foundry_datastores": analyze_foundry_datastores,
            "foundry_endpoints": analyze_foundry_endpoints,
            "foundry_registry": analyze_foundry_registry,
            "foundry_connections": analyze_foundry_connections,
            "foundry_serverless": analyze_foundry_serverless,
            "foundry_ws_diagnostics": analyze_foundry_ws_diagnostics,
            "foundry_prompt_shields": analyze_foundry_prompt_shields,
            "foundry_model_catalog": analyze_foundry_model_catalog,
            "foundry_data_exfiltration": analyze_foundry_data_exfiltration,
            "custom_api_security": analyze_custom_api_security,
            "custom_data_residency": analyze_custom_data_residency,
            "custom_content_leakage": analyze_custom_content_leakage,
            # D – Entra Identity
            "entra_ai_service_principals": analyze_entra_ai_service_principals,
            "entra_ai_conditional_access": analyze_entra_ai_conditional_access,
            "entra_ai_consent": analyze_entra_ai_consent,
            # E – AI Infrastructure
            "ai_diagnostics": analyze_ai_diagnostics,
            "ai_model_governance": analyze_ai_model_governance,
            "ai_threat_protection": analyze_ai_threat_protection,
            "ai_data_governance": analyze_ai_data_governance,
            # F – Agent Orchestration & Platform Security
            "ai_defender_coverage": analyze_ai_defender_coverage,
            "ai_policy_compliance": analyze_ai_policy_compliance,
            "agent_communication": analyze_agent_communication,
            "agent_governance": analyze_agent_governance,
        }
        all_findings: list[dict] = []
        for cat in categories:
            fn = _CAT_MAP.get(cat)
            if fn:
                all_findings.extend(fn(evidence_index))

        scores = compute_agent_security_scores(all_findings)
        results = {
            "AssessmentId": "targeted",
            "AssessedAt": datetime.now(timezone.utc).isoformat(),
            "SubscriptionCount": len(subs),
            "EvidenceSource": "existing_assessment" if evidence else "none",
            "AgentSecurityScores": scores,
            "Findings": all_findings,
            "FindingCount": len(all_findings),
        }
    else:
        results = await run_ai_agent_security_assessment(creds, evidence=evidence)

    # Apply suppressions
    suppressed_findings: list[dict] = []
    if suppressions:
        active, suppressed_findings = _apply_suppressions(results.get("Findings", []), suppressions)
        results["Findings"] = active
        results["FindingCount"] = len(active)
        results["SuppressedFindings"] = suppressed_findings
        results["SuppressedCount"] = len(suppressed_findings)
        results["AgentSecurityScores"] = compute_agent_security_scores(active)
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

    _print_scores(results.get("AgentSecurityScores", {}))
    for f in results.get("Findings", []):
        _print_finding(f)

    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    base_dir = _REPO_ROOT / "output" / ts
    out_dir = str(base_dir / "AI-Agent-Security")
    json_path = _save_results(results, out_dir)
    html_path = generate_ai_agent_security_report(results, out_dir)
    xlsx_path = generate_ai_agent_security_excel(results, out_dir)
    csv_path = _export_findings_csv(results.get("Findings", []), out_dir)
    ps_path, sh_path = _generate_remediation_scripts(results.get("Findings", []), out_dir)

    # Generate PDFs from all HTML reports
    pdf_paths = await convert_all_html_to_pdf(out_dir)

    _print_header("COMPLETE")
    print(f"  Findings:  {results.get('FindingCount', 0)}")
    if suppressed_findings:
        print(f"  Suppressed: {len(suppressed_findings)}")
    print(f"  Level:     {results.get('AgentSecurityScores', {}).get('OverallLevel', 'unknown').upper()}")
    print(f"  Time:      {elapsed:.1f}s")
    print(f"  JSON:      {json_path}")
    print(f"  Report:    {html_path}")
    print(f"  Excel:     {xlsx_path}")
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
                print(f"\n  CI/CD GATE FAILED: {len(blocking)} findings at or above '{threshold}' severity")
                sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EnterpriseSecurityIQ — AI Agent Security Assessment",
    )
    parser.add_argument("--tenant", required=True, help="Azure AD tenant ID")
    parser.add_argument("--evidence", help="Path to raw-evidence.json from a prior assessment")
    parser.add_argument(
        "--category",
        help="Comma-separated categories: cs_authentication,cs_data_connectors,cs_logging,"
             "cs_channels,cs_knowledge_sources,cs_generative_ai,cs_governance,"
             "cs_connector_security,foundry_network,foundry_identity,"
             "foundry_content_safety,foundry_deployments,foundry_governance,"
             "foundry_compute,foundry_datastores,foundry_endpoints,foundry_registry,"
             "custom_api_security,custom_data_residency,custom_content_leakage,"
             "entra_ai_service_principals,entra_ai_conditional_access,entra_ai_consent,"
             "ai_diagnostics,ai_model_governance,ai_threat_protection,ai_data_governance,"
             "ai_defender_coverage,ai_policy_compliance,agent_communication,"
             "agent_governance",
    )
    parser.add_argument(
        "--previous-run",
        help="Path to a previous ai-agent-security-assessment.json for trend comparison",
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
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
