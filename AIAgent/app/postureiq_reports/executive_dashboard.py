"""
Executive Dashboard — single-page HTML overview.

Renders:
  - Overall compliance score gauge
  - Per-framework score cards
  - Top-N findings by risk
  - Domain coverage heatmap
  - Maturity level badges
"""

from __future__ import annotations

import pathlib
from typing import Any

from app.logger import log
from app.postureiq_reports.shared_theme import (
    esc, get_css, get_js, score_color, severity_badge, status_badge,
    humanize_framework, humanize_domain, SEVERITY_COLORS, DOMAIN_META,
    format_date_short, VERSION,
)


def generate_executive_dashboard(
    results: dict[str, Any],
    tenant_info: dict[str, Any],
    output_dir: str,
    delta: dict[str, Any] | None = None,
) -> str:
    """Create ``executive-dashboard.html`` and return its path."""
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "executive-dashboard.html"

    tenant = esc(tenant_info.get("display_name", tenant_info.get("tenant_id", "")))
    summary = results.get("summary", {})
    score = summary.get("ComplianceScore", 0)
    maturity = summary.get("OverallMaturity", "N/A")
    total = summary.get("TotalControls", 0)
    compliant = summary.get("Compliant", 0)
    non_compliant = summary.get("NonCompliant", 0)
    partial = summary.get("Partial", 0)
    findings = results.get("findings", [])
    fw_summaries = summary.get("FrameworkSummaries", {})
    domain_scores = summary.get("DomainScores", {})

    # ── Stats row ──
    stats = _stat_cards(summary, findings)

    # ── Framework cards ──
    fw_cards = _framework_cards(fw_summaries)

    # ── Score gauge SVG ──
    gauge = _score_gauge(score)

    # ── Top 10 findings ──
    top_findings = _top_findings(findings, 10)

    # ── Domain heatmap ──
    heatmap = _domain_heatmap(domain_scores)

    # ── Delta trend (if available) ──
    trend_section = _trend_section(delta)

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Executive Dashboard — {tenant}</title>
<style>{get_css()}
.dashboard-grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:32px}}
.gauge-wrap{{display:flex;align-items:center;gap:32px;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;grid-column:span 2}}
.maturity-badge{{display:inline-block;padding:4px 12px;border-radius:6px;font-weight:700;font-size:13px;background:var(--primary);color:#fff}}
.fw-card{{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;transition:all .2s}}
.fw-card:hover{{box-shadow:var(--shadow-md);transform:translateY(-2px)}}
.fw-score{{font-size:36px;font-weight:700;font-family:var(--font-mono)}}
.fw-name{{font-size:13px;color:var(--text-secondary);margin-bottom:4px}}
.fw-bar{{height:6px;background:var(--bar-bg);border-radius:3px;margin-top:8px;overflow:hidden}}
.fw-bar-fill{{height:100%;border-radius:3px;transition:width .8s cubic-bezier(.16,1,.3,1)}}
.heatmap-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}}
.heat-cell{{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center;transition:all .2s}}
.heat-cell:hover{{box-shadow:var(--shadow-sm)}}
.heat-score{{font-size:28px;font-weight:700;font-family:var(--font-mono)}}
.heat-name{{font-size:12px;color:var(--text-secondary);margin-top:4px}}
.heat-bar{{height:4px;background:var(--bar-bg);border-radius:2px;margin-top:8px;overflow:hidden}}
.heat-fill{{height:100%;border-radius:2px}}
</style>
</head>
<body>
<a href="#main-content" class="skip-nav">Skip to content</a>
<main class="content" id="main-content" style="max-width:1200px;margin:0 auto;padding:2rem">
<header style="text-align:center;margin-bottom:32px">
  <h1 class="page-title">Executive Compliance Dashboard</h1>
  <p class="meta-bar" style="justify-content:center">
    <span>Tenant: <strong>{tenant}</strong></span>
    <span>Generated: {format_date_short()}</span>
    <span>Maturity: <span class="maturity-badge">{esc(str(maturity))}</span></span>
  </p>
</header>

<div class="dashboard-grid">
  {gauge}
  {stats}
  {fw_cards}
</div>

<section class="section">
<h2>Domain Coverage</h2>
{heatmap}
</section>

<section class="section">
<h2>Top Findings by Risk</h2>
{top_findings}
</section>

{trend_section}

<footer style="text-align:center;padding:2rem 0;opacity:.5;font-size:.85rem">
  PostureIQ v{VERSION}
</footer>
</main>
<script>{get_js()}</script>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    log.info("Executive dashboard → %s", path)
    return str(path)


# ─── Internal helpers ────────────────────────────────────────────────────────


def _score_gauge(score: float) -> str:
    """Inline SVG donut gauge for the overall score."""
    color = score_color(score)
    pct = max(0, min(score, 100))
    dash = pct * 2.51327  # circumference of r=40 is ~251.327
    return f"""<div class="gauge-wrap">
  <svg width="160" height="160" viewBox="0 0 100 100" class="ring">
    <circle cx="50" cy="50" r="40" fill="none" stroke="var(--ring-track)" stroke-width="10"/>
    <circle cx="50" cy="50" r="40" fill="none" stroke="{color}" stroke-width="10"
      stroke-dasharray="{dash:.1f} 251.327" stroke-linecap="round"
      transform="rotate(-90 50 50)" style="transition:stroke-dasharray 1.2s cubic-bezier(.16,1,.3,1)"/>
    <text x="50" y="50" text-anchor="middle" dominant-baseline="central"
      fill="{color}" font-size="22" font-weight="700" font-family="var(--font-mono)">{pct:.0f}%</text>
  </svg>
  <div>
    <div style="font-size:24px;font-weight:700;margin-bottom:8px">Overall Compliance Score</div>
    <div style="color:var(--text-secondary);font-size:14px">Across all evaluated frameworks and controls</div>
  </div>
</div>"""


def _stat_cards(summary: dict, findings: list) -> str:
    crit = summary.get("CriticalFindings", sum(1 for f in findings if f.get("Severity") == "critical"))
    high = summary.get("HighFindings", sum(1 for f in findings if f.get("Severity") == "high"))
    items = [
        (str(summary.get("TotalControls", 0)), "Controls Evaluated", "var(--primary)"),
        (str(summary.get("Compliant", 0)), "Compliant", "var(--success)"),
        (str(summary.get("NonCompliant", 0)), "Non-Compliant", "var(--danger)"),
        (str(crit), "Critical", SEVERITY_COLORS["critical"]),
        (str(high), "High", SEVERITY_COLORS["high"]),
        (str(len(findings)), "Total Findings", "var(--info)"),
    ]
    cards = ""
    for val, label, color in items:
        cards += f"""<div class="stat-card">
  <div class="stat-value" style="color:{color}">{val}</div>
  <div class="stat-label">{label}</div>
</div>"""
    return f'<div class="stat-grid" style="grid-column:span 2">{cards}</div>'


def _framework_cards(fw_summaries: dict) -> str:
    cards = ""
    for fw_key, fw_data in fw_summaries.items():
        score = fw_data.get("Score", fw_data.get("ComplianceScore", 0))
        total = fw_data.get("TotalControls", 0)
        comp = fw_data.get("Compliant", 0)
        color = score_color(score)
        name = humanize_framework(fw_key)
        cards += f"""<div class="fw-card">
  <div class="fw-name">{esc(name)}</div>
  <div class="fw-score" style="color:{color}">{score:.0f}%</div>
  <div style="font-size:12px;color:var(--text-muted)">{comp}/{total} controls</div>
  <div class="fw-bar"><div class="fw-bar-fill" style="width:{score:.0f}%;background:{color}"></div></div>
</div>"""
    return cards


def _domain_heatmap(domain_scores: dict) -> str:
    if not domain_scores:
        return '<p class="dim">No domain scores available.</p>'
    cells = ""
    for key, data in sorted(domain_scores.items(), key=lambda x: x[1].get("Score", 0)):
        score = data.get("Score", 0)
        total = data.get("Total", 0)
        comp = data.get("Compliant", 0)
        color = score_color(score)
        icon = DOMAIN_META.get(key, {}).get("icon", "&#9679;")
        name = humanize_domain(key)
        cells += f"""<div class="heat-cell">
  <div style="font-size:24px;margin-bottom:4px">{icon}</div>
  <div class="heat-score" style="color:{color}">{score:.0f}%</div>
  <div class="heat-name">{esc(name)}</div>
  <div style="font-size:11px;color:var(--text-muted)">{comp}/{total}</div>
  <div class="heat-bar"><div class="heat-fill" style="width:{score:.0f}%;background:{color}"></div></div>
</div>"""
    return f'<div class="heatmap-grid">{cells}</div>'


def _top_findings(findings: list[dict], n: int) -> str:
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    sorted_f = sorted(findings, key=lambda f: sev_rank.get(f.get("Severity", "medium"), 5))[:n]
    if not sorted_f:
        return '<p class="dim">No findings.</p>'
    rows = ""
    for f in sorted_f:
        ctrl = esc(f.get("ControlId", ""))
        desc = esc(f.get("Description", ""))[:140]
        sev = f.get("Severity", "medium")
        rows += f"""<tr>
  <td>{ctrl}</td>
  <td>{severity_badge(sev)}</td>
  <td>{desc}</td>
  <td>{status_badge(f.get('Status', 'non_compliant'))}</td>
</tr>"""
    return f"""<table class="data-table"><thead><tr>
  <th>Control</th><th>Severity</th><th>Description</th><th>Status</th>
</tr></thead><tbody>{rows}</tbody></table>"""


def _trend_section(delta: dict | None) -> str:
    if not delta or not delta.get("score_change"):
        return ""
    rows = ""
    for fw, sc in delta["score_change"].items():
        d = sc.get("delta", 0)
        color = "var(--success)" if d > 0 else ("var(--danger)" if d < 0 else "var(--text-dim)")
        sign = "+" if d > 0 else ""
        rows += f"""<tr>
  <td>{esc(humanize_framework(fw))}</td>
  <td>{sc.get('old', 0):.1f}%</td>
  <td>{sc.get('new', 0):.1f}%</td>
  <td style="color:{color};font-weight:600">{sign}{d:.1f}%</td>
</tr>"""
    return f"""<section class="section">
<h2>Score Trend (vs Previous Run)</h2>
<table class="data-table"><thead><tr>
  <th>Framework</th><th>Previous</th><th>Current</th><th>Change</th>
</tr></thead><tbody>{rows}</tbody></table>
</section>"""
