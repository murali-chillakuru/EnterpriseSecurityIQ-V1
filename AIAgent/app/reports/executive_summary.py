"""
Executive Summary — HTML and Markdown
Concise overview: compliance posture, key metrics, assessed environment,
framework breakdown, top 10 risks.
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

def generate_executive_summary_html(
    results: dict[str, Any],
    evidence: list[dict],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    ts = datetime.now(timezone.utc)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "executive-summary.html"

    inv = extract_inventory(evidence)
    env = get_environment_summary(inv)
    summary = results.get("summary", {})
    findings = results.get("findings", [])
    missing = results.get("missing_evidence", [])
    domain_scores = summary.get("DomainScores", {})
    tenant = tenant_info or {}

    score = summary.get("ComplianceScore", 0)
    sc = score_color(score)
    frameworks = summary.get("Frameworks", ["FedRAMP"])
    fw_label = ", ".join(frameworks)
    top_risks = _top_risks(findings)
    report_id = f"CIQ-{ts.strftime('%Y%m%d-%H%M%S')}"

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>EnterpriseSecurityIQ &mdash; Executive Summary</title>
<style>{get_css()}</style>
</head>
<body>
<a href="#main-content" class="skip-nav">Skip to content</a>
<div class="layout">
  <nav class="sidebar" role="navigation" aria-label="Report sections">
    <h2>EnterpriseSecurityIQ</h2>
    <span class="version">Executive Summary</span>
    <div class="nav-group">Sections</div>
    <nav>
      <a href="#doc-control" class="active">Document Control</a>
      <a href="#overview">Overview</a>
      <a href="#metrics">Key Metrics</a>
      <a href="#environment">Assessed Environment</a>
      <a href="#frameworks">Framework Breakdown</a>
      <a href="#domains">Domain Scores</a>
      <a href="#top-risks">Top 10 Risks</a>
      <a href="#next-steps">Next Steps</a>
    </nav>
    <button class="theme-btn" onclick="toggleTheme()">Switch to Light</button>
  </nav>
  <main class="content" id="main-content">
    <section id="doc-control" class="section">
      <h2>Document Control</h2>
      <table class="doc-control-table">
        <tr><th>Report ID</th><td><code>{report_id}</code></td></tr>
        <tr><th>Assessment Name</th><td>EnterpriseSecurityIQ {esc(fw_label)} Executive Summary</td></tr>
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
      <h1 class="page-title">Executive Summary</h1>
      <p style="color:var(--text-secondary)">EnterpriseSecurityIQ {esc(fw_label)} Assessment &mdash;
      Tenant: <code>{esc(tenant.get('TenantId', tenant.get('tenant_id', '')))}</code>
      &mdash; {format_date_short(ts)}</p>

      <div class="score-display" style="margin:24px 0">
        <svg class="ring" viewBox="0 0 120 120" width="180" height="180">
          <circle cx="60" cy="60" r="50" fill="none" stroke="var(--ring-track)" stroke-width="10"/>
          <circle cx="60" cy="60" r="50" fill="none" stroke="{sc}" stroke-width="10"
                  stroke-dasharray="{score * 3.14:.1f} 314" stroke-dashoffset="0"
                  stroke-linecap="round" transform="rotate(-90 60 60)"/>
          <text x="60" y="60" text-anchor="middle" dominant-baseline="central"
                font-size="24" font-weight="700" fill="{sc}">{score:.0f}%</text>
        </svg>
      </div>
    </section>

    <section id="metrics" class="section">
      <h2>Key Metrics</h2>
      <div class="stat-grid">
        <div class="stat-card"><div class="stat-value" style="color:{sc}">{score:.1f}%</div><div class="stat-label">Compliance Score</div></div>
        <div class="stat-card"><div class="stat-value">{summary.get('TotalControls', 0)}</div><div class="stat-label">Total Controls</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#107C10">{summary.get('Compliant', 0)}</div><div class="stat-label">Compliant</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#D13438">{summary.get('NonCompliant', 0)}</div><div class="stat-label">Non-Compliant</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#FFB900">{summary.get('Partial', 0)}</div><div class="stat-label">Partial</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#A8A6A3">{summary.get('MissingEvidence', 0)}</div><div class="stat-label">Missing Evidence</div></div>
      </div>
      <h3>Finding Severity</h3>
      <table class="data-table">
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>
          <tr><td>{severity_badge('critical')}</td><td>{summary.get('CriticalFindings', 0)}</td></tr>
          <tr><td>{severity_badge('high')}</td><td>{summary.get('HighFindings', 0)}</td></tr>
          <tr><td>{severity_badge('medium')}</td><td>{summary.get('MediumFindings', 0)}</td></tr>
        </tbody>
      </table>
    </section>

    <section id="environment" class="section">
      <h2>Assessed Environment</h2>
      <table class="data-table">
        <thead><tr><th>Category</th><th>Count</th></tr></thead>
        <tbody>
          {"".join(f'<tr><td>{esc(k)}</td><td>{v:,}</td></tr>' for k, v in env.items())}
        </tbody>
      </table>
    </section>

    <section id="frameworks" class="section">
      <h2>Framework Breakdown</h2>
      {_fw_cards_html(summary.get("FrameworkSummaries", {}), score, sc)}
    </section>

    <section id="domains" class="section">
      <h2>Domain Scores</h2>
      <div class="domain-grid">
        {_domain_cards_html(domain_scores)}
      </div>
    </section>

    <section id="top-risks" class="section">
      <h2>Top 10 Risks</h2>
      {_top_risks_html(top_risks)}
    </section>

    <section id="next-steps" class="section">
      <h2>Recommended Next Steps</h2>
      <ol style="color:var(--text-secondary);margin:8px 0 0 24px">
        <li><strong>Immediate (0-30 days):</strong> Address all Critical and High severity findings.</li>
        <li><strong>Short-term (30-90 days):</strong> Remediate Medium severity gaps and strengthen monitoring.</li>
        <li><strong>Long-term (90-180 days):</strong> Address remaining Low findings and optimize compliance posture.</li>
        <li>Resolve Access Denied issues ({len(access_denied or [])}) for comprehensive coverage.</li>
        <li>Re-run assessment after remediation to measure improvement.</li>
      </ol>
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

    log.info("Executive summary HTML: %s", path)
    return str(path)


def _fw_cards_html(fw_summaries: dict, overall_score: float, sc: str) -> str:
    if not fw_summaries:
        return f'<p style="color:var(--text-secondary)">Single framework; overall score <strong style="color:{sc}">{overall_score:.1f}%</strong>.</p>'
    cards = []
    for fk, fv in fw_summaries.items():
        s = fv.get("ComplianceScore", 0)
        c = score_color(s)
        cards.append(f"""
        <div class="domain-card">
          <div class="domain-icon">&#128203;</div>
          <div class="domain-name">{esc(fv.get('FrameworkName', fk))}</div>
          <div class="domain-score" style="color:{c}">{s:.0f}%</div>
          <div class="domain-detail">{fv.get('Compliant', 0)}/{fv.get('TotalControls', 0)} compliant</div>
        </div>""")
    return f'<div class="domain-grid">{"".join(cards)}</div>'


def _domain_cards_html(scores: dict) -> str:
    if not scores:
        return '<p class="empty">No domain data.</p>'
    cards = []
    for domain, data in scores.items():
        meta = DOMAIN_META.get(domain, {"name": domain.replace("_", " ").title(), "icon": "&#128193;"})
        s = data.get("Score", 0)
        c = score_color(s)
        cards.append(f"""
        <div class="domain-card">
          <div class="domain-icon">{meta['icon']}</div>
          <div class="domain-name">{meta['name']}</div>
          <div class="domain-score" style="color:{c}">{s:.0f}%</div>
          <div class="domain-detail">{data.get('Compliant', 0)}/{data.get('Total', 0)} compliant</div>
        </div>""")
    return "\n".join(cards)


def _top_risks(findings: list[dict]) -> list[dict]:
    nc = [f for f in findings if f.get("Status") == "non_compliant"]
    nc.sort(key=lambda x: sev_order(x.get("Severity", "medium")))
    seen: set[str] = set()
    top: list[dict] = []
    for f in nc:
        cid = f.get("ControlId", "")
        if cid in seen:
            continue
        seen.add(cid)
        top.append(f)
        if len(top) >= 10:
            break
    return top


def _top_risks_html(risks: list[dict]) -> str:
    if not risks:
        return '<p class="empty">No non-compliant findings.</p>'
    rows = "".join(
        f'<tr><td>{i}</td><td><code>{esc(r.get("ControlId", ""))}</code></td>'
        f'<td>{esc(r.get("ControlTitle", ""))}</td>'
        f'<td>{severity_badge(r.get("Severity", "medium"))}</td>'
        f'<td>{esc(r.get("Description", "")[:200])}</td></tr>'
        for i, r in enumerate(risks, 1)
    )
    return f'<table class="data-table"><thead><tr><th>#</th><th>Control</th><th>Title</th><th>Severity</th><th>Description</th></tr></thead><tbody>{rows}</tbody></table>'


# ═════════════════════════════════════════════════════════════════════════
# MARKDOWN
# ═════════════════════════════════════════════════════════════════════════

def generate_executive_summary_md(
    results: dict[str, Any],
    evidence: list[dict],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    ts = datetime.now(timezone.utc)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "executive-summary.md"

    inv = extract_inventory(evidence)
    env = get_environment_summary(inv)
    summary = results.get("summary", {})
    findings = results.get("findings", [])
    tenant = tenant_info or {}

    score = summary.get("ComplianceScore", 0)
    frameworks = summary.get("Frameworks", ["FedRAMP"])
    fw_label = ", ".join(frameworks)
    top_risks = _top_risks(findings)

    lines: list[str] = []
    W = lines.append

    W(f"# EnterpriseSecurityIQ — Executive Summary\n")
    W(f"**{fw_label} Assessment** | Tenant: `{tenant.get('TenantId', tenant.get('tenant_id', ''))}` "
      f"| {ts.strftime('%Y-%m-%d %H:%M UTC')}\n")
    W(f"## Overall Compliance Score: {score:.1f}%\n")

    W("## Key Metrics\n")
    W("| Metric | Value |")
    W("|---|---|")
    W(f"| Total Controls | {summary.get('TotalControls', 0)} |")
    W(f"| Compliant | {summary.get('Compliant', 0)} |")
    W(f"| Non-Compliant | {summary.get('NonCompliant', 0)} |")
    W(f"| Partial | {summary.get('Partial', 0)} |")
    W(f"| Missing Evidence | {summary.get('MissingEvidence', 0)} |")
    W(f"| Critical Findings | {summary.get('CriticalFindings', 0)} |")
    W(f"| High Findings | {summary.get('HighFindings', 0)} |")
    W(f"| Medium Findings | {summary.get('MediumFindings', 0)} |")
    W(f"| Evidence Records | {summary.get('TotalEvidence', 0):,} |")
    W("")

    W("## Assessed Environment\n")
    W("| Category | Count |")
    W("|---|---|")
    for k, v in env.items():
        W(f"| {k} | {v:,} |")
    W("")

    # Framework breakdown
    fw_summaries = summary.get("FrameworkSummaries", {})
    if fw_summaries:
        W("## Framework Breakdown\n")
        W("| Framework | Score | Compliant | Non-Compliant | Missing |")
        W("|---|---|---|---|---|")
        for fk, fv in fw_summaries.items():
            W(f"| {fv.get('FrameworkName', fk)} | {fv.get('ComplianceScore', 0):.1f}% "
              f"| {fv.get('Compliant', 0)} | {fv.get('NonCompliant', 0)} | {fv.get('MissingEvidence', 0)} |")
        W("")

    # Domain scores
    domain_scores = summary.get("DomainScores", {})
    if domain_scores:
        W("## Domain Scores\n")
        W("| Domain | Score | Compliant | Total |")
        W("|---|---|---|---|")
        for d, data in domain_scores.items():
            W(f"| {d.replace('_', ' ').title()} | {data.get('Score', 0):.0f}% | {data.get('Compliant', 0)} | {data.get('Total', 0)} |")
        W("")

    # Top 10 Risks
    W("## Top 10 Risks\n")
    if top_risks:
        W("| # | Control | Title | Severity | Description |")
        W("|---|---|---|---|---|")
        for i, r in enumerate(top_risks, 1):
            W(f"| {i} | `{r.get('ControlId', '')}` | {r.get('ControlTitle', '')} "
              f"| **{r.get('Severity', '').upper()}** | {r.get('Description', '')[:150]} |")
        W("")
    else:
        W("No non-compliant findings.\n")

    W("## Recommended Next Steps\n")
    W("1. **Immediate (0-30 days):** Address all Critical and High severity findings.")
    W("2. **Short-term (30-90 days):** Remediate Medium severity gaps.")
    W("3. **Long-term (90-180 days):** Address remaining Low findings.")
    W(f"4. Resolve Access Denied issues ({len(access_denied or [])}) for comprehensive coverage.")
    W("5. Re-run assessment after remediation.\n")

    W(f"\n---\n*Generated by EnterpriseSecurityIQ AI Agent v1.0 — {ts.strftime('%Y-%m-%d')} — CONFIDENTIAL*\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log.info("Executive summary MD: %s", path)
    return str(path)
