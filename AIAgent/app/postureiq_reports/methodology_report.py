"""
Methodology Report — Professional HTML explaining how the assessment was conducted.
Provides transparency and confidence to both technical and non-technical audiences.
"""

from __future__ import annotations
import pathlib
from datetime import datetime, timezone
from typing import Any
from app.postureiq_reports.shared_theme import (
    get_css, get_js, esc, score_color, format_date, format_date_short,
    DOMAIN_META, SEVERITY_COLORS, STATUS_LABELS,
)
from app.logger import log


def _ring_svg(score: float, size: int = 120) -> str:
    """SVG donut ring for a score value."""
    r = size // 2 - 8
    circ = 2 * 3.14159 * r
    offset = circ * (1 - score / 100)
    col = score_color(score)
    return (
        f'<svg width="{size}" height="{size}" class="ring">'
        f'<circle cx="{size//2}" cy="{size//2}" r="{r}" fill="none" stroke="var(--ring-track)" stroke-width="10"/>'
        f'<circle cx="{size//2}" cy="{size//2}" r="{r}" fill="none" stroke="{col}" stroke-width="10" '
        f'stroke-dasharray="{circ}" stroke-dashoffset="{offset}" '
        f'stroke-linecap="round" transform="rotate(-90 {size//2} {size//2})"/>'
        f'<text x="50%" y="50%" text-anchor="middle" dy=".35em" '
        f'font-size="22" font-weight="700" fill="var(--text)" font-family="var(--font-mono)">'
        f'{score:.0f}%</text></svg>'
    )


def _pipeline_diagram() -> str:
    """Visual flow diagram of the 4-phase assessment pipeline."""
    phases = [
        ("&#128269;", "Phase 1", "Evidence Collection",
         "Collectors query Azure ARM APIs and Microsoft Graph endpoints to gather "
         "resource configurations, policy assignments, RBAC roles, Entra ID settings, "
         "conditional access policies, and security configurations."),
        ("&#9878;&#65039;", "Phase 2", "Compliance Evaluation",
         "The evaluation engine maps collected evidence to framework controls using "
         "domain-specific evaluators. Each control is scored as Compliant, Non-Compliant, "
         "Partial, or Missing Evidence based on evidence rules."),
        ("&#128202;", "Phase 3", "Report Generation",
         "Results are rendered into multiple formats: HTML compliance reports, executive "
         "summaries, gap analyses, Excel workbooks, data exports (CSV/JSON), and raw evidence "
         "archives for audit trail."),
        ("&#128190;", "Phase 4", "Data Archival",
         "All evidence, findings, and reports are persisted to the output directory with "
         "full traceability. Raw evidence is stored in categorized JSON files for "
         "independent verification."),
    ]
    cards = []
    for i, (icon, label, title, desc) in enumerate(phases):
        arrow = '<div style="text-align:center;font-size:24px;color:var(--primary);margin:8px 0">&#8595;</div>' if i < len(phases) - 1 else ""
        cards.append(
            f'<div class="stat-card" style="text-align:left;padding:24px">'
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">'
            f'<span style="font-size:28px">{icon}</span>'
            f'<div><div style="font-size:11px;color:var(--primary);font-weight:700;text-transform:uppercase;letter-spacing:1px">{label}</div>'
            f'<div style="font-size:16px;font-weight:600">{title}</div></div></div>'
            f'<p style="font-size:13px;color:var(--text-secondary);line-height:1.6">{desc}</p>'
            f'</div>{arrow}'
        )
    return "".join(cards)


def _collector_table(collector_stats: list[dict]) -> str:
    """Table showing each collector, status, record count, and duration."""
    if not collector_stats:
        return '<p class="empty">No collector statistics available.</p>'
    rows = []
    for s in sorted(collector_stats, key=lambda x: x.get("name", "")):
        name = esc(s.get("name", ""))
        source = esc(s.get("source", ""))
        count = s.get("records", 0)
        duration = s.get("duration", 0)
        status = s.get("status", "success")
        if status == "access_denied":
            badge = '<span class="badge" style="background:#FFB900">ACCESS DENIED</span>'
        elif status == "failed":
            badge = '<span class="badge" style="background:#D13438">FAILED</span>'
        else:
            badge = '<span class="badge" style="background:#107C10">OK</span>'
        rows.append(
            f'<tr><td><code>{name}</code></td><td>{source}</td>'
            f'<td style="text-align:right">{count:,}</td>'
            f'<td style="text-align:right">{duration:.1f}s</td>'
            f'<td>{badge}</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr>'
        '<th>Collector</th><th>Source</th><th>Records</th><th>Duration</th><th>Status</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
    )


def _evidence_type_table(evidence: list[dict]) -> str:
    """Table showing evidence types and counts."""
    type_counts: dict[str, int] = {}
    for e in evidence:
        et = e.get("EvidenceType", "unknown")
        type_counts[et] = type_counts.get(et, 0) + 1
    if not type_counts:
        return '<p class="empty">No evidence collected.</p>'
    rows = []
    for et, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        rows.append(f'<tr><td><code>{esc(et)}</code></td><td style="text-align:right">{count:,}</td></tr>')
    return (
        '<table class="data-table"><thead><tr>'
        '<th>Evidence Type</th><th>Count</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
    )


def _framework_controls_table(results: dict) -> str:
    """Show per-framework control coverage."""
    fw_summaries = results.get("summary", {}).get("FrameworkSummaries", {})
    if not fw_summaries:
        return ""
    rows = []
    for fw, s in sorted(fw_summaries.items()):
        total = s.get("TotalControls", 0)
        compliant = s.get("Compliant", 0)
        non_compliant = s.get("NonCompliant", 0)
        partial = s.get("Partial", 0)
        missing = s.get("MissingEvidence", 0)
        score = s.get("ComplianceScore", 0)
        col = score_color(score)
        rows.append(
            f'<tr><td><strong>{esc(fw)}</strong></td>'
            f'<td style="text-align:right">{total}</td>'
            f'<td style="text-align:right;color:#107C10">{compliant}</td>'
            f'<td style="text-align:right;color:#D13438">{non_compliant}</td>'
            f'<td style="text-align:right;color:#FFB900">{partial}</td>'
            f'<td style="text-align:right;color:#A19F9D">{missing}</td>'
            f'<td style="text-align:right;color:{col};font-weight:700">{score:.1f}%</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr>'
        '<th>Framework</th><th>Total Controls</th><th>Compliant</th>'
        '<th>Non-Compliant</th><th>Partial</th><th>Missing</th><th>Score</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
    )


def _access_denied_table(access_denied: list[dict]) -> str:
    """Show APIs that returned access denied."""
    if not access_denied:
        return '<p style="color:var(--success)">&#10003; All APIs accessible — no permission issues detected.</p>'
    rows = []
    for ad in access_denied:
        rows.append(
            f'<tr><td><code>{esc(ad.get("collector", ""))}</code></td>'
            f'<td>{esc(ad.get("source", ""))}</td>'
            f'<td><code>{esc(ad.get("api", ""))}</code></td>'
            f'<td>{ad.get("status_code", 403)}</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr>'
        '<th>Collector</th><th>Source</th><th>API</th><th>HTTP Status</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
    )


def _evaluation_explanation() -> str:
    """Explain how the evaluation engine works."""
    return """
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-bottom:24px">
      <div class="stat-card" style="text-align:left;padding:20px">
        <h4 style="color:var(--primary);margin-bottom:8px">&#128270; Evidence Matching</h4>
        <p style="font-size:13px;color:var(--text-secondary)">Each framework control specifies required evidence types.
        The engine queries the evidence pool for matching records and invokes
        domain-specific evaluator functions.</p>
      </div>
      <div class="stat-card" style="text-align:left;padding:20px">
        <h4 style="color:var(--primary);margin-bottom:8px">&#9878;&#65039; Domain Evaluators</h4>
        <p style="font-size:13px;color:var(--text-secondary)">Six evaluation domains — Access Control, Identity, Data Protection,
        Logging, Network, and Governance — contain specialized logic that checks
        resource configuration against compliance requirements.</p>
      </div>
      <div class="stat-card" style="text-align:left;padding:20px">
        <h4 style="color:var(--primary);margin-bottom:8px">&#127919; Scoring Model</h4>
        <p style="font-size:13px;color:var(--text-secondary)">Controls are scored as: <strong>Compliant</strong> (all checks pass),
        <strong>Non-Compliant</strong> (any critical check fails), <strong>Partial</strong> (some checks pass),
        or <strong>Missing Evidence</strong> (required data not collected).</p>
      </div>
      <div class="stat-card" style="text-align:left;padding:20px">
        <h4 style="color:var(--primary);margin-bottom:8px">&#128202; Severity Assignment</h4>
        <p style="font-size:13px;color:var(--text-secondary)">Each framework control has a pre-assigned severity (critical, high, medium, low)
        from the framework mapping files. Findings inherit this severity for prioritisation
        in gap analysis and remediation planning.</p>
      </div>
    </div>
    """


def _data_sources_section() -> str:
    """Describe the data sources used."""
    sources = [
        ("Azure Resource Manager (ARM)", "Resource inventory, policy assignments, RBAC roles, diagnostic settings, "
         "network configuration, compute resources, security contacts, Defender plans"),
        ("Microsoft Graph API", "Entra ID users, conditional access policies, directory roles, applications, "
         "service principals, audit logs, sign-in logs, identity protection events, governance"),
        ("Azure Policy Insights", "Policy compliance states, non-compliant resources, policy definitions"),
        ("Azure Monitor", "Log Analytics workspaces, alerts, action groups, diagnostic settings"),
        ("Azure Key Vault", "Key Vault configurations, access policies, network rules"),
    ]
    rows = []
    for name, desc in sources:
        rows.append(
            f'<tr><td><strong>{esc(name)}</strong></td>'
            f'<td style="font-size:13px;color:var(--text-secondary)">{esc(desc)}</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr>'
        '<th>Data Source</th><th>Data Collected</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
    )


def _integrity_section(evidence: list[dict], results: dict) -> str:
    """Show integrity and transparency metrics."""
    total_evidence = len(evidence)
    total_controls = results.get("summary", {}).get("TotalControls", 0)
    total_findings = len(results.get("findings", []))
    unique_types = len(set(e.get("EvidenceType", "") for e in evidence))
    unique_sources = len(set(e.get("Source", "") for e in evidence))
    unique_collectors = len(set(e.get("Collector", "") for e in evidence))

    return f"""
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-value">{total_evidence:,}</div>
        <div class="stat-label">Evidence Records</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{unique_types}</div>
        <div class="stat-label">Evidence Types</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{unique_collectors}</div>
        <div class="stat-label">Collectors Executed</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{unique_sources}</div>
        <div class="stat-label">Data Sources</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{total_controls}</div>
        <div class="stat-label">Controls Evaluated</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{total_findings}</div>
        <div class="stat-label">Findings Generated</div>
      </div>
    </div>
    """


def generate_methodology_html(
    results: dict[str, Any],
    evidence: list[dict],
    tenant_info: dict,
    output_dir: str,
    access_denied: list[dict] | None = None,
    collector_stats: list[dict] | None = None,
    elapsed_seconds: float = 0,
) -> str:
    """Generate a comprehensive methodology HTML report. Returns file path."""
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    filepath = out / "methodology-report.html"

    now = datetime.now(timezone.utc)
    tenant_name = tenant_info.get("display_name") or tenant_info.get("DisplayName", "N/A")
    tenant_id = tenant_info.get("tenant_id") or tenant_info.get("TenantId", "N/A")
    score = results.get("summary", {}).get("ComplianceScore", 0)
    frameworks = results.get("summary", {}).get("Frameworks", [])
    fw_list = ", ".join(frameworks) if frameworks else "N/A"

    ad = access_denied or []
    stats = collector_stats or []

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Assessment Methodology — PostureIQ</title>
<style>{get_css()}</style>
</head>
<body>
<a href="#main-content" class="skip-nav">Skip to content</a>
<div class="layout">
  <aside class="sidebar" role="navigation" aria-label="Report sections">
    <h2>PostureIQ</h2>
    <div class="version">Methodology Report</div>
    <button class="theme-btn" onclick="toggleTheme()">Switch to Light</button>
    <nav>
      <div class="nav-group">Contents</div>
      <a href="#overview">Overview</a>
      <a href="#pipeline">Assessment Pipeline</a>
      <a href="#data-sources">Data Sources</a>
      <a href="#collectors">Collector Execution</a>
      <a href="#evidence">Evidence Summary</a>
      <a href="#evaluation">Evaluation Engine</a>
      <a href="#frameworks">Framework Coverage</a>
      <a href="#transparency">Transparency Metrics</a>
      <a href="#access-denied">Permission Gaps</a>
      <a href="#outputs">Output Artefacts</a>
      <a href="#verification">Independent Verification</a>
    </nav>
  </aside>
  <main class="content" id="main-content">
    <div class="section" id="overview">
      <h1 class="page-title">Assessment Methodology</h1>
      <div class="meta-bar">
        <span>Tenant: <strong>{esc(tenant_name)}</strong> ({esc(tenant_id)})</span>
        <span>Generated: {format_date_short(now)}</span>
        <span>Duration: {elapsed_seconds:.0f}s</span>
      </div>
      <div class="conf-notice">
        &#128196; This report describes <strong>how</strong> the PostureIQ assessment was conducted,
        what data sources were queried, how controls were evaluated, and how results were produced.
        It is designed to provide full transparency and auditability for compliance stakeholders.
      </div>

      <div style="display:flex;align-items:center;gap:32px;flex-wrap:wrap;margin-bottom:24px">
        {_ring_svg(score, 100)}
        <div>
          <div style="font-size:24px;font-weight:700">{score:.1f}% Compliance Score</div>
          <div style="font-size:14px;color:var(--text-secondary)">Frameworks: {esc(fw_list)}</div>
        </div>
      </div>
    </div>

    <div class="section" id="pipeline">
      <h2>&#128736; Assessment Pipeline</h2>
      <p style="color:var(--text-secondary);margin-bottom:16px">
        PostureIQ follows a deterministic 4-phase pipeline. Each phase is isolated and produces
        traceable outputs. No LLM or AI inference is used in evidence collection or compliance
        evaluation — all checks are rule-based and reproducible.
      </p>
      {_pipeline_diagram()}
    </div>

    <div class="section" id="data-sources">
      <h2>&#128451; Data Sources</h2>
      <p style="color:var(--text-secondary);margin-bottom:16px">
        Evidence is collected exclusively from first-party Microsoft APIs using the authenticated
        user's credentials. All API calls are read-only — no resources are modified.
      </p>
      {_data_sources_section()}
    </div>

    <div class="section" id="collectors">
      <h2>&#9881;&#65039; Collector Execution Details</h2>
      <p style="color:var(--text-secondary);margin-bottom:16px">
        Collectors run in parallel batches (Azure: 4 concurrent, Entra: 3 concurrent) to respect
        API throttling limits. Each collector handles pagination, retries with exponential backoff,
        and graceful access-denied detection.
      </p>
      {_collector_table(stats)}
    </div>

    <div class="section" id="evidence">
      <h2>&#128203; Evidence Summary by Type</h2>
      <p style="color:var(--text-secondary);margin-bottom:16px">
        Every piece of evidence is categorized by type and stored with full metadata including
        source, collector, timestamp, resource ID, and raw API response data.
      </p>
      {_evidence_type_table(evidence)}
    </div>

    <div class="section" id="evaluation">
      <h2>&#9878;&#65039; Evaluation Engine</h2>
      <p style="color:var(--text-secondary);margin-bottom:16px">
        The compliance evaluation engine uses deterministic, rule-based logic — no AI/ML inference.
        Each framework control maps to specific evidence types and evaluation functions.
      </p>
      {_evaluation_explanation()}
    </div>

    <div class="section" id="frameworks">
      <h2>&#128209; Framework Control Coverage</h2>
      {_framework_controls_table(results)}
    </div>

    <div class="section" id="transparency">
      <h2>&#128200; Transparency &amp; Integrity Metrics</h2>
      <p style="color:var(--text-secondary);margin-bottom:16px">
        These metrics demonstrate the breadth and depth of the assessment. All data is preserved
        in the <code>raw/</code> directory for independent audit.
      </p>
      {_integrity_section(evidence, results)}
    </div>

    <div class="section" id="access-denied">
      <h2>&#128274; Permission Gaps</h2>
      <p style="color:var(--text-secondary);margin-bottom:16px">
        When the authenticated user lacks permissions for specific APIs, PostureIQ records the
        gap transparently rather than silently omitting data. Controls that depend on inaccessible
        data are marked as "Missing Evidence".
      </p>
      {_access_denied_table(ad)}
    </div>

    <div class="section" id="outputs">
      <h2>&#128194; Output Artefacts</h2>
      <p style="color:var(--text-secondary);margin-bottom:16px">
        The assessment produces the following output artefacts for each framework:
      </p>
      <table class="data-table">
        <thead><tr><th>Artefact</th><th>Format</th><th>Purpose</th></tr></thead>
        <tbody>
          <tr><td>Compliance Report</td><td>HTML, Markdown</td><td>Full control-level assessment with findings and remediation guidance</td></tr>
          <tr><td>Executive Summary</td><td>HTML, Markdown</td><td>High-level overview for leadership and stakeholders</td></tr>
          <tr><td>Gap Analysis</td><td>HTML, Markdown</td><td>Non-compliant and partial controls with prioritised remediation plan</td></tr>
          <tr><td>Excel Workbook</td><td>XLSX</td><td>Sortable/filterable compliance data, gaps, and summary in one workbook</td></tr>
          <tr><td>Data Exports</td><td>CSV, JSON</td><td>Machine-readable control results, findings, and missing evidence</td></tr>
          <tr><td>Raw Evidence</td><td>JSON</td><td>Complete API response data for independent verification</td></tr>
          <tr><td>Methodology Report</td><td>HTML</td><td>This document — assessment process transparency</td></tr>
        </tbody>
      </table>
    </div>

    <div class="section" id="verification">
      <h2>&#128270; Independent Verification</h2>
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
        <h4 style="color:var(--primary);margin-bottom:12px">How to verify these results</h4>
        <ol style="color:var(--text-secondary);font-size:13px;line-height:2;padding-left:20px">
          <li><strong>Raw Evidence:</strong> Open the <code>raw/</code> directory to inspect the actual API responses collected from your tenant.</li>
          <li><strong>Control Mappings:</strong> Review the framework mapping files in <code>AIAgent/app/postureiq_frameworks/</code> to see exactly which evidence types each control requires.</li>
          <li><strong>Evaluator Logic:</strong> The evaluation rules are in <code>AIAgent/app/postureiq_evaluators/</code> — deterministic Python functions with no external dependencies.</li>
          <li><strong>Data Exports:</strong> The <code>control-results.csv</code> and <code>findings.csv</code> files can be independently analysed in any spreadsheet tool.</li>
          <li><strong>Reproducibility:</strong> Re-running the assessment with the same credentials against the same tenant will produce consistent results (within API data freshness).</li>
        </ol>
      </div>
      <div class="conf-notice">
        &#128274; <strong>Security note:</strong> This assessment operates in read-only mode. No resources, configurations,
        or policies are modified. All API calls use the authenticated user's existing permissions.
      </div>
    </div>

    <div style="text-align:center;color:var(--text-muted);font-size:12px;padding:32px 0;border-top:1px solid var(--border)">
      PostureIQ Methodology Report &middot; Generated {format_date(now)} &middot; v2.0
    </div>
  </main>
</div>
<script>{get_js()}</script>
</body>
</html>"""

    filepath.write_text(html, encoding="utf-8")
    log.info("Methodology report: %s", filepath)
    return str(filepath)
