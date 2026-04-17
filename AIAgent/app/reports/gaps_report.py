"""
Gaps Report — HTML and Markdown
Focused on non-compliant and partial controls with detailed per-gap analysis,
affected resources, remediation steps, and effort matrix.
"""

from __future__ import annotations
import hashlib
import pathlib
from datetime import datetime, timezone
from typing import Any
from app.logger import log
from app.reports.shared_theme import (
    esc, get_css, get_js, SEVERITY_COLORS, DOMAIN_META,
    score_color, severity_badge, status_badge, sev_order, format_ts, format_date_short,
)
from app.reports.inventory import extract_inventory, get_environment_summary


# ═════════════════════════════════════════════════════════════════════════
# HTML
# ═════════════════════════════════════════════════════════════════════════

def generate_gaps_report_html(
    results: dict[str, Any],
    evidence: list[dict],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    ts = datetime.now(timezone.utc)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "gaps-report.html"

    inv = extract_inventory(evidence)
    summary = results.get("summary", {})
    controls = results.get("control_results", [])
    findings = results.get("findings", [])
    missing = results.get("missing_evidence", [])
    tenant = tenant_info or {}

    score = summary.get("ComplianceScore", 0)
    sc = score_color(score)
    frameworks = summary.get("Frameworks", ["FedRAMP"])
    fw_label = ", ".join(frameworks)

    nc_controls = [c for c in controls if c.get("Status") in ("non_compliant", "partial")]
    nc_findings = [f for f in findings if f.get("Status") in ("non_compliant", "partial")]
    gap_groups = _group_gaps(nc_findings)
    report_id = f"CIQ-{ts.strftime('%Y%m%d-%H%M%S')}"

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>EnterpriseSecurityIQ &mdash; Gaps Analysis Report</title>
<style>{get_css()}</style>
</head>
<body>
<a href="#main-content" class="skip-nav">Skip to content</a>
<div class="layout">
  <nav class="sidebar" role="navigation" aria-label="Report sections">
    <h2>EnterpriseSecurityIQ</h2>
    <span class="version">Gaps Report</span>
    <div class="nav-group">Sections</div>
    <nav>
      <a href="#doc-control" class="active">Document Control</a>
      <a href="#overview">Overview</a>
      <a href="#environment">Environment</a>
      <a href="#gaps-summary">Gaps Summary</a>
      <a href="#risk-categories">Risk Categories</a>
      <a href="#critical-gaps">Critical &amp; High</a>
      <a href="#medium-gaps">Medium</a>
      <a href="#low-gaps">Low</a>
      <a href="#missing-evidence">Missing Evidence</a>
      <a href="#effort-matrix">Effort Matrix</a>
    </nav>
    <button class="theme-btn" onclick="toggleTheme()">Switch to Light</button>
  </nav>
  <main class="content" id="main-content">

    <!-- Document Control -->
    <section id="doc-control" class="section">
      <h2>Document Control</h2>
      <table class="doc-control-table">
        <tr><th>Report ID</th><td><code>{report_id}</code></td></tr>
        <tr><th>Assessment Name</th><td>EnterpriseSecurityIQ {esc(fw_label)} Gaps Analysis</td></tr>
        <tr><th>Date Generated</th><td>{format_ts(ts)}</td></tr>
        <tr><th>Tenant ID</th><td><code>{esc(tenant.get('TenantId', tenant.get('tenant_id', 'N/A')))}</code></td></tr>
        <tr><th>Tenant Name</th><td>{esc(tenant.get('DisplayName', tenant.get('display_name', 'Unknown')))}</td></tr>
        <tr><th>Frameworks Evaluated</th><td>{esc(fw_label)}</td></tr>
        <tr><th>Classification</th><td>CONFIDENTIAL &mdash; Authorized Recipients Only</td></tr>
        <tr><th>Tool</th><td>EnterpriseSecurityIQ AI Agent v1.0</td></tr>
      </table>
      <div class="conf-notice">
        <strong>CONFIDENTIALITY NOTICE:</strong> This document contains sensitive security and compliance
        information about the assessed environment. Distribution is restricted to authorized personnel only.
      </div>
      <h3>Audit Attestation</h3>
      <table class="doc-control-table">
        <tr><th>Assessment Scope</th><td>Control-plane configuration review of Azure and Microsoft Entra ID resources</td></tr>
        <tr><th>Data Integrity</th><td>All evidence collected via read-only API calls; no tenant modifications were made</td></tr>
        <tr><th>Evidence Records</th><td>{summary.get('TotalEvidence', 0):,} records collected and evaluated</td></tr>
        <tr><th>Report Hash (SHA-256)</th><td><code id="report-hash">Computed at render</code></td></tr>
        <tr><th>Assessment Period</th><td>{format_date_short(ts)} (point-in-time snapshot)</td></tr>
      </table>
    </section>

    <section id="overview" class="section">
      <h1 class="page-title">EnterpriseSecurityIQ &mdash; Gaps Analysis Report</h1>
      <p style="color:var(--text-secondary)">{esc(fw_label)} Assessment &mdash;
      Tenant: <code>{esc(tenant.get('TenantId', tenant.get('tenant_id', '')))}</code>
      &mdash; {format_date_short(ts)}</p>

      <div class="stat-grid">
        <div class="stat-card"><div class="stat-value" style="color:{sc}">{score:.1f}%</div><div class="stat-label">Compliance Score</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#D13438">{len(nc_controls)}</div><div class="stat-label">Gap Controls</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#D13438">{summary.get('CriticalFindings', 0)}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#E87400">{summary.get('HighFindings', 0)}</div><div class="stat-label">High</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#FFB900">{summary.get('MediumFindings', 0)}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#A8A6A3">{len(missing)}</div><div class="stat-label">Missing Evidence</div></div>
      </div>
    </section>

    <section id="environment" class="section">
      <h2>Assessed Environment</h2>
      <table class="data-table">
        <thead><tr><th>Resource Category</th><th>Count</th></tr></thead>
        <tbody>{"".join(f'<tr><td>{esc(k)}</td><td>{v:,}</td></tr>' for k, v in get_environment_summary(inv).items())}</tbody>
      </table>
    </section>

    <section id="gaps-summary" class="section">
      <h2>Gaps Summary</h2>
      <table class="data-table">
        <thead><tr><th>Control</th><th>Title</th><th>Framework</th><th>Domain</th><th>Severity</th><th>Status</th><th>Reason / Key Finding</th></tr></thead>
        <tbody>{_gaps_summary_rows(nc_controls, nc_findings)}</tbody>
      </table>
    </section>

    <section id="risk-categories" class="section">
      <h2>Risk Category Definitions</h2>
      <div class="risk-def" style="border-left:3px solid #D13438">
        <h4 style="color:#D13438">CRITICAL / HIGH RISK</h4>
        <p>Direct security impact with immediate exploitation potential. Missing fundamental controls. <strong>Remediation: 0-30 days.</strong></p>
      </div>
      <div class="risk-def" style="border-left:3px solid #FFB900">
        <h4 style="color:#FFB900">MEDIUM RISK</h4>
        <p>Configuration gaps exploitable under certain conditions. <strong>Remediation: 30-90 days.</strong></p>
      </div>
      <div class="risk-def" style="border-left:3px solid #107C10">
        <h4 style="color:#107C10">LOW RISK</h4>
        <p>Best-practice deviations with minimal direct security impact. <strong>Remediation: 90-180 days.</strong></p>
      </div>
    </section>

    {_gap_sections_html(gap_groups, inv)}

    <section id="missing-evidence" class="section">
      <h2>Missing Evidence ({len(missing)})</h2>
      {_missing_html(missing)}
    </section>

    <section id="effort-matrix" class="section">
      <h2>Remediation Effort Matrix</h2>
      {_effort_matrix_html(nc_findings)}
    </section>

    <footer style="text-align:center;color:var(--text-muted);font-size:12px;padding:32px 0;border-top:1px solid var(--border)">
      Generated by EnterpriseSecurityIQ AI Agent v1.0 &mdash; {format_date_short(ts)} &mdash; CONFIDENTIAL
    </footer>
  </main>
</div>
<script>{get_js()}</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    # Compute report hash for audit trail
    report_hash = hashlib.sha256(html.encode("utf-8")).hexdigest()
    html = html.replace("Computed at render", report_hash)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    log.info("Gaps report HTML: %s", path)
    return str(path)


def _gaps_summary_rows(controls: list, findings: list | None = None) -> str:
    # Build lookup: ControlId -> first finding description
    finding_desc: dict[str, str] = {}
    if findings:
        for f in sorted(findings, key=lambda x: sev_order(x.get("Severity", "medium"))):
            cid = f.get("ControlId", "")
            if cid and cid not in finding_desc:
                finding_desc[cid] = f.get("Description", "")
    rows = []
    for c in sorted(controls, key=lambda x: (sev_order(x.get("Severity", "medium")), x.get("ControlId", ""))):
        cid = c.get("ControlId", "")
        reason = esc(finding_desc.get(cid, ""))
        rows.append(
            f'<tr><td><code>{esc(cid)}</code></td>'
            f'<td>{esc(c.get("ControlTitle", ""))}</td>'
            f'<td>{esc(c.get("Framework", ""))}</td>'
            f'<td>{esc(DOMAIN_META.get(c.get("Domain", ""), {}).get("name", c.get("Domain", "")))}</td>'
            f'<td>{severity_badge(c.get("Severity", "medium"))}</td>'
            f'<td>{status_badge(c.get("Status", ""))}</td>'
            f'<td style="font-size:12px;max-width:300px">{reason}</td></tr>'
        )
    return "\n".join(rows)


def _group_gaps(findings: list) -> dict[str, list]:
    groups: dict[str, list] = {}
    for f in sorted(findings, key=lambda x: sev_order(x.get("Severity", "medium"))):
        sev = f.get("Severity", "medium").lower()
        groups.setdefault(sev, []).append(f)
    return groups


def _gap_sections_html(groups: dict[str, list], inv: dict) -> str:
    parts = []
    level_map = {
        "critical": ("critical-gaps", "Critical & High Risk Gaps", "#D13438"),
        "high": ("critical-gaps", "Critical & High Risk Gaps", "#D13438"),
        "medium": ("medium-gaps", "Medium Risk Gaps", "#FFB900"),
        "low": ("low-gaps", "Low Risk Gaps", "#107C10"),
    }
    seen_sections: set[str] = set()
    for sev in ["critical", "high", "medium", "low"]:
        items = groups.get(sev, [])
        if not items:
            continue
        section_id, heading, color = level_map[sev]
        if section_id in seen_sections:
            # For critical+high combined, rows already included
            continue
        seen_sections.add(section_id)
        combined = items
        if sev == "critical":
            combined = items + groups.get("high", [])
        total = len(combined)
        parts.append(f'<section id="{section_id}" class="section">')
        parts.append(f'<h2 style="color:{color}">{heading} ({total})</h2>')
        parts.append('<table class="data-table"><thead><tr>'
                     '<th>Control</th><th>Title</th><th>Severity</th>'
                     '<th>Framework</th><th>Domain</th><th>Description</th><th>Remediation</th>'
                     '</tr></thead><tbody>')
        for f in combined:
            parts.append(_gap_finding_row(f))
        parts.append('</tbody></table>')
        parts.append('</section>')
    return "\n".join(parts)


def _gap_finding_row(f: dict) -> str:
    cid = esc(f.get("ControlId", ""))
    title = esc(f.get("ControlTitle", ""))
    desc = esc(f.get("Description", ""))
    rec = esc(f.get("Recommendation", ""))
    sev = f.get("Severity", "medium")
    fw = esc(f.get("Framework", ""))
    domain = esc(DOMAIN_META.get(f.get("Domain", ""), {}).get("name", f.get("Domain", "")))
    return (
        f'<tr><td><code>{cid}</code></td><td>{title}</td>'
        f'<td>{severity_badge(sev)}</td><td>{fw}</td><td>{domain}</td>'
        f'<td style="font-size:12px;max-width:280px">{desc}</td>'
        f'<td style="font-size:12px;max-width:280px;color:var(--success)">{rec}</td></tr>'
    )


def _missing_html(missing: list) -> str:
    if not missing:
        return '<p class="empty">All evidence collected.</p>'

    cat_colors = {
        "License / Feature Required": "#e74c3c",
        "Resource Not Deployed": "#3498db",
        "Feature Not Configured": "#f39c12",
        "Insufficient Permissions": "#e67e22",
        "API / Collector Issue": "#9b59b6",
    }

    # Summary by category
    cat_counts: dict[str, int] = {}
    for m in missing:
        cat = m.get("PrimaryCategory", "Unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    legend = '<div style="margin-bottom:16px;display:flex;gap:12px;flex-wrap:wrap">'
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        color = cat_colors.get(cat, "#95a5a6")
        legend += (
            f'<span style="display:inline-flex;align-items:center;gap:4px;font-size:12px">'
            f'<span style="display:inline-block;width:10px;height:10px;border-radius:2px;'
            f'background:{color}"></span>{esc(cat)} ({count})</span>'
        )
    legend += '</div>'

    # Build detailed cards per control
    cards = []
    for m in missing:
        cid = esc(m.get("ControlId", ""))
        sev = m.get("Severity", "medium")
        fw = esc(m.get("Framework", ""))
        cat = m.get("PrimaryCategory", "Unknown")
        cat_color = cat_colors.get(cat, "#95a5a6")

        types_html = ""
        for td in m.get("TypesDetail", []):
            etype = esc(td.get("EvidenceType", ""))
            dname = esc(td.get("DisplayName", etype))
            source = esc(td.get("Source", ""))
            explanation = esc(td.get("Explanation", ""))
            resolution = td.get("Resolution", "").replace("\n", "<br>")
            tcat = td.get("Category", "")
            tcat_color = cat_colors.get(tcat, "#95a5a6")

            types_html += f'''
              <div style="margin:8px 0;padding:10px 12px;background:var(--bg-secondary);
                border-radius:6px;border-left:3px solid {tcat_color}">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                  <strong style="font-size:13px">{dname}</strong>
                  <span style="font-size:11px;padding:2px 8px;border-radius:10px;
                    background:{tcat_color}20;color:{tcat_color};font-weight:600">{esc(tcat)}</span>
                </div>
                <code style="font-size:11px;color:var(--text-muted)">{etype}</code>
                <span style="font-size:11px;color:var(--text-muted);margin-left:8px">({source})</span>
                <p style="font-size:12px;margin:6px 0 4px;color:var(--text-secondary)">{explanation}</p>
                <details style="font-size:12px;margin-top:4px">
                  <summary style="cursor:pointer;color:var(--primary);font-weight:500">Resolution Steps</summary>
                  <div style="margin-top:6px;padding:8px;background:var(--bg-primary);
                    border-radius:4px;line-height:1.6">{resolution}</div>
                </details>
              </div>'''

        # Fallback if TypesDetail not populated
        if not types_html:
            types_list = ", ".join(m.get("MissingTypes", []))
            types_html = f'<p style="font-size:12px">{esc(types_list)}</p>'

        cards.append(f'''
          <div style="margin-bottom:12px;padding:14px;border:1px solid var(--border);
            border-radius:8px;border-left:4px solid {cat_color}">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
              <div>
                <code style="font-size:13px;font-weight:600">{cid}</code>
                {severity_badge(sev)}
                <span style="font-size:11px;color:var(--text-muted);margin-left:6px">{fw}</span>
              </div>
              <span style="font-size:11px;padding:3px 10px;border-radius:10px;
                background:{cat_color}15;color:{cat_color};font-weight:600;
                border:1px solid {cat_color}30">{esc(cat)}</span>
            </div>
            {types_html}
          </div>''')

    return legend + "\n".join(cards)


def _effort_matrix_html(findings: list) -> str:
    if not findings:
        return '<p class="empty">No gaps to remediate.</p>'
    categories = {"critical": "Immediate (0-14d)", "high": "Urgent (0-30d)", "medium": "Short-term (30-90d)", "low": "Long-term (90-180d)"}
    rows = []
    for sev, timeline in categories.items():
        group = [f for f in findings if f.get("Severity", "").lower() == sev]
        if group:
            color = SEVERITY_COLORS.get(sev, "#A8A6A3")
            rows.append(f'<tr><td style="color:{color};font-weight:600">{sev.upper()}</td><td>{len(group)}</td><td>{timeline}</td></tr>')
    return f'<table class="data-table"><thead><tr><th>Severity</th><th>Count</th><th>Remediation Timeline</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'


# ═════════════════════════════════════════════════════════════════════════
# MARKDOWN
# ═════════════════════════════════════════════════════════════════════════

def generate_gaps_report_md(
    results: dict[str, Any],
    evidence: list[dict],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    ts = datetime.now(timezone.utc)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "gaps-report.md"

    inv = extract_inventory(evidence)
    summary = results.get("summary", {})
    controls = results.get("control_results", [])
    findings = results.get("findings", [])
    missing = results.get("missing_evidence", [])
    tenant = tenant_info or {}

    score = summary.get("ComplianceScore", 0)
    frameworks = summary.get("Frameworks", ["FedRAMP"])
    fw_label = ", ".join(frameworks)

    nc_controls = [c for c in controls if c.get("Status") in ("non_compliant", "partial")]
    nc_findings = [f for f in findings if f.get("Status") in ("non_compliant", "partial")]

    lines: list[str] = []
    W = lines.append

    W(f"# EnterpriseSecurityIQ — Gaps Analysis Report\n")
    W(f"**{fw_label} Assessment** | Tenant: `{tenant.get('TenantId', tenant.get('tenant_id', ''))}` "
      f"| {ts.strftime('%Y-%m-%d %H:%M UTC')}\n")

    W("## Overview\n")
    W("| Metric | Value |")
    W("|---|---|")
    W(f"| Compliance Score | {score:.1f}% |")
    W(f"| Gap Controls | {len(nc_controls)} |")
    W(f"| Critical Findings | {summary.get('CriticalFindings', 0)} |")
    W(f"| High Findings | {summary.get('HighFindings', 0)} |")
    W(f"| Medium Findings | {summary.get('MediumFindings', 0)} |")
    W(f"| Missing Evidence | {len(missing)} |")
    W("")

    # Assessed Environment
    env_summary = get_environment_summary(inv)
    if env_summary:
        W("## Assessed Environment\n")
        W("| Resource Category | Count |")
        W("|---|---|")
        for k, v in env_summary.items():
            W(f"| {k} | {v:,} |")
        W("")

    # Gaps Summary with reason
    finding_desc: dict[str, str] = {}
    for f in sorted(nc_findings, key=lambda x: _sev_order(x.get("Severity", "medium"))):
        cid = f.get("ControlId", "")
        if cid and cid not in finding_desc:
            finding_desc[cid] = f.get("Description", "")

    W("## Gaps Summary\n")
    W("| Control | Title | Framework | Domain | Severity | Status | Reason / Key Finding |")
    W("|---|---|---|---|---|---|---|")
    for c in sorted(nc_controls, key=lambda x: (_sev_order(x.get("Severity", "medium")), x.get("ControlId", ""))):
        sev = c.get("Severity", "medium").upper()
        status = c.get("Status", "").replace("_", " ").title()
        reason = finding_desc.get(c.get("ControlId", ""), "")
        W(f"| `{c.get('ControlId', '')}` | {c.get('ControlTitle', '')} | {c.get('Framework', '')} "
          f"| {c.get('Domain', '')} | **{sev}** | {status} | {reason} |")
    W("")

    W("## Risk Category Definitions\n")
    W("- **CRITICAL/HIGH:** Direct security impact. Remediation: 0-30 days.")
    W("- **MEDIUM:** Configuration gaps. Remediation: 30-90 days.")
    W("- **LOW:** Best-practice deviations. Remediation: 90-180 days.\n")

    # Tabular gap findings per severity
    groups = _group_gaps(nc_findings)
    for sev in ["critical", "high", "medium", "low"]:
        items = groups.get(sev, [])
        if not items:
            continue
        W(f"## {sev.upper()} Risk Gaps ({len(items)})\n")
        W("| Control | Title | Description | Remediation |")
        W("|---|---|---|---|")
        for f in items:
            cid = f.get("ControlId", "")
            title = f.get("ControlTitle", "")
            desc = f.get("Description", "")
            rec = f.get("Recommendation", "")
            W(f"| `{cid}` | {title} | {desc} | {rec} |")
        W("")

    W(f"## Missing Evidence ({len(missing)})\n")
    if missing:
        # Category summary
        cat_counts: dict[str, int] = {}
        for m in missing:
            cat = m.get("PrimaryCategory", "Unknown")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            W(f"- **{cat}**: {count} control(s)")
        W("")

        W("| Control | Severity | Category | Missing Evidence | Explanation |")
        W("|---|---|---|---|---|")
        for m in missing:
            types_detail = m.get("TypesDetail", [])
            if types_detail:
                names = ", ".join(td.get("DisplayName", td.get("EvidenceType", "")) for td in types_detail)
                explanations = "; ".join(td.get("Explanation", "") for td in types_detail if td.get("Explanation"))
            else:
                names = ", ".join(m.get("MissingTypes", []))
                explanations = ""
            W(f"| `{m.get('ControlId', '')}` | {m.get('Severity', '').upper()} "
              f"| {m.get('PrimaryCategory', '')} | {names} | {explanations} |")
        W("")

        # Detailed resolution per missing evidence item
        W("### Resolution Details\n")
        for m in missing:
            cid = m.get("ControlId", "")
            for td in m.get("TypesDetail", []):
                dname = td.get("DisplayName", td.get("EvidenceType", ""))
                explanation = td.get("Explanation", "")
                resolution = td.get("Resolution", "")
                W(f"#### `{cid}` — {dname}\n")
                if explanation:
                    W(f"**Why:** {explanation}\n")
                if resolution:
                    W(f"**Resolution:**\n")
                    for line in resolution.split("\n"):
                        if line.strip():
                            W(f"{line.strip()}")
                    W("")
        W("")

    W("## Remediation Effort Matrix\n")
    W("| Severity | Count | Timeline |")
    W("|---|---|---|")
    for sev, timeline in [("critical", "0-14 days"), ("high", "0-30 days"), ("medium", "30-90 days"), ("low", "90-180 days")]:
        group = [f for f in nc_findings if f.get("Severity", "").lower() == sev]
        if group:
            W(f"| **{sev.upper()}** | {len(group)} | {timeline} |")
    W("")

    W(f"\n---\n*Generated by EnterpriseSecurityIQ AI Agent v1.0 — {ts.strftime('%Y-%m-%d')} — CONFIDENTIAL*\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info("Gaps report MD: %s", path)
    return str(path)


def _sev_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev.lower(), 4)
