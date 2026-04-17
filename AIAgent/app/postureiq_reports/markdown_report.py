"""
Markdown Report Generator
Produces a human-readable Markdown compliance report.
"""

from __future__ import annotations
import pathlib
from datetime import datetime, timezone
from typing import Any
from app.logger import log


def generate_markdown_report(
    results: dict[str, Any],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    """Generate a Markdown report and return the file path."""
    if not results:
        raise ValueError("Cannot generate Markdown report: results dict is empty")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"PostureIQ-Report-{ts}.md"

    summary = results.get("summary", {})
    controls = results.get("control_results", [])
    findings = results.get("findings", [])
    missing = results.get("missing_evidence", [])
    tenant = tenant_info or {}

    lines: list[str] = []

    # Header
    lines.append("# PostureIQ Compliance Report\n")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
    if tenant.get("display_name"):
        lines.append(f"**Tenant:** {tenant['display_name']} (`{tenant.get('tenant_id', '')}`)\n")
    lines.append(f"**Frameworks:** {', '.join(summary.get('Frameworks', ['FedRAMP']))}\n")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary\n")
    score = summary.get("ComplianceScore", 0)
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| **Compliance Score** | **{score:.1f}%** |")
    lines.append(f"| Total Controls | {summary.get('TotalControls', 0)} |")
    lines.append(f"| Compliant | {summary.get('Compliant', 0)} |")
    lines.append(f"| Non-Compliant | {summary.get('NonCompliant', 0)} |")
    lines.append(f"| Partial | {summary.get('Partial', 0)} |")
    lines.append(f"| Missing Evidence | {summary.get('MissingEvidence', 0)} |")
    lines.append(f"| Total Findings | {summary.get('TotalFindings', 0)} |")
    lines.append(f"| Evidence Records | {summary.get('TotalEvidence', 0)} |")
    lines.append("")

    # Severity breakdown
    lines.append("### Findings by Severity\n")
    lines.append(f"- **Critical:** {summary.get('CriticalFindings', 0)}")
    lines.append(f"- **High:** {summary.get('HighFindings', 0)}")
    lines.append(f"- **Medium:** {summary.get('MediumFindings', 0)}")
    lines.append("")

    # Domain scores
    domain_scores = summary.get("DomainScores", {})
    if domain_scores:
        lines.append("### Domain Scores\n")
        lines.append("| Domain | Score | Compliant | Total |")
        lines.append("|---|---|---|---|")
        for domain, ds in sorted(domain_scores.items()):
            lines.append(f"| {domain} | {ds.get('Score', 0):.1f}% | {ds.get('Compliant', 0)} | {ds.get('Total', 0)} |")
        lines.append("")

    # Framework summaries
    fw_summaries = summary.get("FrameworkSummaries", {})
    if fw_summaries:
        lines.append("## Framework Results\n")
        for fw_key, fw in fw_summaries.items():
            lines.append(f"### {fw.get('FrameworkName', fw_key)}\n")
            lines.append(f"- Score: **{fw.get('ComplianceScore', 0):.1f}%**")
            lines.append(f"- Controls: {fw.get('TotalControls', 0)} total, "
                         f"{fw.get('Compliant', 0)} compliant, "
                         f"{fw.get('NonCompliant', 0)} non-compliant")
            lines.append("")

    # Non-compliant controls
    non_compliant = [c for c in controls if c.get("Status") == "non_compliant"]
    if non_compliant:
        lines.append("## Non-Compliant Controls\n")
        lines.append("| Control | Title | Severity | Domain | Findings |")
        lines.append("|---|---|---|---|---|")
        for c in sorted(non_compliant, key=lambda x: _sev_order(x.get("Severity", "medium"))):
            lines.append(
                f"| {c['ControlId']} | {c.get('ControlTitle', '')} | "
                f"{c.get('Severity', 'medium').upper()} | {c.get('Domain', '')} | "
                f"{c.get('FindingCount', 0)} |"
            )
        lines.append("")

    # Critical and high findings detail
    critical_high = [f for f in findings
                     if f.get("Severity") in ("critical", "high")
                     and f.get("Status") == "non_compliant"]
    if critical_high:
        lines.append("## Critical & High Findings\n")
        for f in critical_high:
            sev = f.get("Severity", "high").upper()
            lines.append(f"### [{sev}] {f.get('ControlId', '')} — {f.get('ControlTitle', '')}\n")
            lines.append(f"- **Description:** {f.get('Description', '')}")
            if f.get("Recommendation"):
                lines.append(f"- **Recommendation:** {f['Recommendation']}")
            lines.append("")

    # Missing evidence
    if missing:
        lines.append("## Missing Evidence\n")
        lines.append("| Control | Severity | Missing Types |")
        lines.append("|---|---|---|")
        for m in missing:
            lines.append(
                f"| {m['ControlId']} | {m.get('Severity', 'medium').upper()} | "
                f"{', '.join(m.get('MissingTypes', []))} |"
            )
        lines.append("")

    # Access Denied
    if access_denied:
        lines.append("## Access Denied\n")
        lines.append("The following collectors were blocked due to insufficient permissions.\n")
        lines.append("| Collector | Source | API | Status |")
        lines.append("|---|---|---|---|")
        for ad in access_denied:
            lines.append(
                f"| {ad.get('collector', 'Unknown')} | {ad.get('source', 'Unknown')} | "
                f"{ad.get('api', 'Unknown')} | HTTP {ad.get('status_code', 403)} |"
            )
        lines.append("")
        lines.append("> **Note:** Your account does not have the required permissions for the above APIs. "
                      "To collect this data, ensure your account has the appropriate role assignments.\n")

    # Footer
    lines.append("---\n")
    lines.append("*Generated by PostureIQ AI Agent v1.0*\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log.info("Markdown report: %s", path)
    return str(path)


def _sev_order(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 4)
