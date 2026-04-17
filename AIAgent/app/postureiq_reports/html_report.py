"""
HTML Report Generator
Professional blog-style FedRAMP compliance report with Microsoft Fluent Design.
"""

from __future__ import annotations
import pathlib
from datetime import datetime, timezone
from typing import Any
from app.logger import log

# Domain display names and icons
DOMAIN_META = {
    "access": {"name": "Access Control", "icon": "🔐"},
    "identity": {"name": "Identity & Authentication", "icon": "🪪"},
    "data_protection": {"name": "Data Protection", "icon": "🛡️"},
    "logging": {"name": "Logging & Monitoring", "icon": "📊"},
    "network": {"name": "Network Security", "icon": "🌐"},
    "governance": {"name": "Governance & Risk", "icon": "⚖️"},
}

SEVERITY_COLORS = {
    "critical": "#D13438",
    "high": "#F7630C",
    "medium": "#FFB900",
    "low": "#107C10",
}

STATUS_LABELS = {
    "compliant": ("Compliant", "#107C10"),
    "non_compliant": ("Non-Compliant", "#D13438"),
    "partial": ("Partial", "#FFB900"),
    "missing_evidence": ("Missing Evidence", "#A8A6A3"),
    "not_assessed": ("Not Assessed", "#706E6C"),
}


def generate_html_report(
    results: dict[str, Any],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"PostureIQ-Report-{ts}.html"

    summary = results.get("summary", {})
    controls = results.get("control_results", [])
    findings = results.get("findings", [])
    missing = results.get("missing_evidence", [])
    domain_scores = summary.get("DomainScores", {})
    tenant = tenant_info or {}

    score = summary.get("ComplianceScore", 0)
    score_color = "#107C10" if score >= 80 else "#FFB900" if score >= 60 else "#D13438"
    frameworks = summary.get("Frameworks", ["FedRAMP"])
    fw_label = ", ".join(frameworks)

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PostureIQ — {fw_label} Assessment Report</title>
<style>
{_get_css()}
</style>
</head>
<body>
<a href="#main-content" class="skip-nav">Skip to content</a>
<div class="layout">
  <nav class="sidebar" role="navigation" aria-label="Report sections">
    <div class="sidebar-header">
      <h2>PostureIQ</h2>
      <span class="version">AI Agent v1.0</span>
    </div>
    <ul class="nav-links">
      <li><a href="#overview" class="active">📋 Overview</a></li>
      <li><a href="#score">📈 Compliance Score</a></li>
      <li><a href="#frameworks">🏗️ Framework Summaries</a></li>
      <li><a href="#domains">🏛️ Domain Analysis</a></li>
      <li><a href="#controls">📜 Control Results</a></li>
      <li><a href="#findings">🔍 Findings</a></li>
      <li><a href="#roadmap">🗺️ Remediation Roadmap</a></li>
      <li><a href="#missing">⚠️ Missing Evidence</a></li>
      <li><a href="#access-denied">🚫 Access Denied</a></li>
    </ul>
    <div class="sidebar-footer">
      <small>Generated {datetime.now(timezone.utc).strftime('%B %d, %Y %H:%M UTC')}</small>
    </div>
  </nav>
  <main class="content" id="main-content">

    <!-- Overview -->
    <section id="overview" class="section">
      <h1 class="page-title">{fw_label} Compliance Assessment</h1>
      <div class="meta-bar">
        <span>🏢 {_esc(tenant.get('DisplayName', tenant.get('display_name', 'Unknown Tenant')))}</span>
        <span>🔑 {_esc(tenant.get('TenantId', tenant.get('tenant_id', 'N/A')))}</span>
        <span>📅 {datetime.now(timezone.utc).strftime('%B %d, %Y')}</span>
      </div>
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-value" style="color:{score_color}">{score:.0f}%</div>
          <div class="stat-label">Compliance Score</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{summary.get('TotalControls', 0)}</div>
          <div class="stat-label">Controls Assessed</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:#107C10">{summary.get('Compliant', 0)}</div>
          <div class="stat-label">Compliant</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:#D13438">{summary.get('NonCompliant', 0)}</div>
          <div class="stat-label">Non-Compliant</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{summary.get('TotalFindings', 0)}</div>
          <div class="stat-label">Total Findings</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{summary.get('TotalEvidence', 0):,}</div>
          <div class="stat-label">Evidence Records</div>
        </div>
      </div>
    </section>

    <!-- Score Ring -->
    <section id="score" class="section">
      <h2>Compliance Score</h2>
      <div class="score-display">
        <svg class="ring" viewBox="0 0 120 120" width="200" height="200">
          <circle cx="60" cy="60" r="50" fill="none" stroke="#383640" stroke-width="10"/>
          <circle cx="60" cy="60" r="50" fill="none" stroke="{score_color}" stroke-width="10"
                  stroke-dasharray="{score * 3.14:.1f} 314" stroke-dashoffset="0"
                  stroke-linecap="round" transform="rotate(-90 60 60)"/>
          <text x="60" y="60" text-anchor="middle" dominant-baseline="central"
                font-size="24" font-weight="700" fill="{score_color}">{score:.0f}%</text>
        </svg>
        <div class="score-breakdown">
          <div class="score-row"><span class="dot" style="background:#107C10"></span> Compliant: {summary.get('Compliant', 0)}</div>
          <div class="score-row"><span class="dot" style="background:#D13438"></span> Non-Compliant: {summary.get('NonCompliant', 0)}</div>
          <div class="score-row"><span class="dot" style="background:#FFB900"></span> Partial: {summary.get('Partial', 0)}</div>
          <div class="score-row"><span class="dot" style="background:#A8A6A3"></span> Missing Evidence: {summary.get('MissingEvidence', 0)}</div>
        </div>
      </div>
      <div class="severity-summary">
        <h3>Findings by Severity</h3>
        <div class="severity-bars">
          {_severity_bar('Critical', summary.get('CriticalFindings', 0), '#D13438', summary.get('TotalFindings', 1))}
          {_severity_bar('High', summary.get('HighFindings', 0), '#F7630C', summary.get('TotalFindings', 1))}
          {_severity_bar('Medium', summary.get('MediumFindings', 0), '#FFB900', summary.get('TotalFindings', 1))}
        </div>
      </div>
    </section>

    <!-- Domain Analysis -->
    <section id="frameworks" class="section">
      <h2>Framework Summaries</h2>
      {_framework_summary_cards(summary.get("FrameworkSummaries", {}))}
    </section>

    <!-- Domain Analysis -->
    <section id="domains" class="section">
      <h2>Domain Analysis</h2>
      <div class="domain-grid">
        {_domain_cards(domain_scores)}
      </div>
    </section>

    <!-- Control Results -->
    <section id="controls" class="section">
      <h2>Control Results ({len(controls)})</h2>
      <table class="data-table">
        <thead>
          <tr><th>Control</th><th>Title</th><th>Framework</th><th>Domain</th><th>Severity</th><th>Status</th><th>Findings</th></tr>
        </thead>
        <tbody>
          {_control_rows(controls)}
        </tbody>
      </table>
    </section>

    <!-- Findings -->
    <section id="findings" class="section">
      <h2>Findings ({len(findings)})</h2>
      {_finding_cards(findings)}
    </section>

    <!-- Missing Evidence -->
    <section id="roadmap" class="section">
      <h2>Remediation Roadmap</h2>
      {_remediation_roadmap(findings)}
    </section>

    <!-- Missing Evidence -->
    <section id="missing" class="section">
      <h2>Missing Evidence ({len(missing)})</h2>
      {_missing_cards(missing) if missing else '<p class="empty">All evidence types collected successfully.</p>'}
    </section>

    <!-- Access Denied -->
    <section id="access-denied" class="section">
      <h2>Access Denied ({len(access_denied or [])})</h2>
      {_access_denied_cards(access_denied)}
    </section>

  </main>
</div>
<script>{_get_js()}</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    log.info("HTML report: %s", path)
    return str(path)


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _framework_summary_cards(fw_summaries: dict) -> str:
    if not fw_summaries:
        return '<p class="empty">Single framework assessment.</p>'
    cards = []
    for fw_key, fws in fw_summaries.items():
        s = fws.get("ComplianceScore", 0)
        c = "#107C10" if s >= 80 else "#FFB900" if s >= 60 else "#D13438"
        cards.append(f"""
        <div class="domain-card">
          <div class="domain-icon">📋</div>
          <div class="domain-name">{_esc(fws.get('FrameworkName', fw_key))}</div>
          <div class="domain-score" style="color:{c}">{s:.0f}%</div>
          <div class="domain-detail">{fws.get('Compliant', 0)}/{fws.get('TotalControls', 0)} compliant</div>
          <div class="domain-detail" style="color:var(--ms-red)">{fws.get('NonCompliant', 0)} non-compliant</div>
        </div>""")
    return f'<div class="domain-grid">{"".join(cards)}</div>'


def _remediation_roadmap(findings: list) -> str:
    """Build priority-ordered remediation roadmap from non-compliant findings."""
    nc_findings = [f for f in findings if f.get("Status") == "non_compliant"]
    if not nc_findings:
        return '<p class="empty">No remediation actions needed — all controls are compliant.</p>'

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    nc_findings.sort(key=lambda f: sev_order.get(f.get("Severity", "medium"), 2))

    # Group by severity
    groups: dict[str, list] = {}
    for f in nc_findings:
        sev = f.get("Severity", "medium")
        groups.setdefault(sev, []).append(f)

    html_parts = []
    priority = 1
    for sev in ["critical", "high", "medium", "low"]:
        items = groups.get(sev, [])
        if not items:
            continue
        color = SEVERITY_COLORS.get(sev, "#A8A6A3")
        html_parts.append(f'<h3 style="color:{color}">Priority {priority}: {sev.upper()} ({len(items)} items)</h3>')
        html_parts.append('<div class="roadmap-items">')
        seen = set()
        for f in items:
            rec = f.get("Recommendation", "")
            desc = f.get("Description", "")
            key = rec or desc
            if key in seen:
                continue
            seen.add(key)
            cid = _esc(f.get("ControlId", ""))
            fw = _esc(f.get("Framework", ""))
            html_parts.append(f"""
            <div class="finding-card non-compliant">
              <div class="finding-header">
                <code>{cid}</code>
                <span class="badge" style="background:{color}">{sev.upper()}</span>
                <span style="color:var(--text-muted);font-size:11px">{fw}</span>
              </div>
              <p class="finding-desc">{_esc(desc)}</p>
              {"<div class='remediation'><strong>Action:</strong> " + _esc(rec) + "</div>" if rec else ""}
            </div>""")
        html_parts.append('</div>')
        priority += 1

    return "\n".join(html_parts)


def _severity_bar(label, count, color, total):
    pct = (count / total * 100) if total > 0 else 0
    return f'<div class="sev-row"><span class="sev-label">{label}</span><div class="sev-track"><div class="sev-fill" style="width:{pct:.0f}%;background:{color}"></div></div><span class="sev-count">{count}</span></div>'


def _domain_cards(scores: dict) -> str:
    cards = []
    for domain, data in scores.items():
        meta = DOMAIN_META.get(domain, {"name": domain.title(), "icon": "📁"})
        s = data.get("Score", 0)
        c = "#107C10" if s >= 80 else "#FFB900" if s >= 60 else "#D13438"
        cards.append(f"""
        <div class="domain-card">
          <div class="domain-icon">{meta['icon']}</div>
          <div class="domain-name">{meta['name']}</div>
          <div class="domain-score" style="color:{c}">{s:.0f}%</div>
          <div class="domain-detail">{data.get('Compliant', 0)}/{data.get('Total', 0)} compliant</div>
        </div>""")
    return "\n".join(cards)


def _control_rows(controls: list) -> str:
    rows = []
    for c in sorted(controls, key=lambda x: x.get("ControlId", "")):
        cid = _esc(c.get("ControlId", ""))
        title = _esc(c.get("ControlTitle", ""))
        domain = c.get("Domain", "")
        sev = c.get("Severity", "medium")
        status_key = c.get("Status", "not_assessed")
        label, color = STATUS_LABELS.get(status_key, ("?", "#706E6C"))
        sev_color = SEVERITY_COLORS.get(sev, "#A8A6A3")
        fc = c.get("FindingCount", 0)
        fw = _esc(c.get("Framework", ""))
        rows.append(
            f'<tr><td><code>{cid}</code></td><td>{title}</td>'
            f'<td>{fw}</td>'
            f'<td>{_esc(DOMAIN_META.get(domain, {}).get("name", domain))}</td>'
            f'<td><span class="badge" style="background:{sev_color}">{sev.upper()}</span></td>'
            f'<td><span class="badge" style="background:{color}">{label}</span></td>'
            f'<td>{fc}</td></tr>'
        )
    return "\n".join(rows)


def _finding_cards(findings: list) -> str:
    if not findings:
        return '<p class="empty">No findings to display.</p>'
    cards = []
    for f in findings:
        cid = _esc(f.get("ControlId", ""))
        desc = _esc(f.get("Description", ""))
        rec = _esc(f.get("Recommendation", ""))
        status_key = f.get("Status", "not_assessed")
        label, color = STATUS_LABELS.get(status_key, ("?", "#706E6C"))
        sev = f.get("Severity", "medium")
        sev_color = SEVERITY_COLORS.get(sev, "#A8A6A3")
        cards.append(f"""
        <div class="finding-card {"non-compliant" if status_key == "non_compliant" else ""}">
          <div class="finding-header">
            <code>{cid}</code>
            <span class="badge" style="background:{sev_color}">{sev.upper()}</span>
            <span class="badge" style="background:{color}">{label}</span>
          </div>
          <p class="finding-desc">{desc}</p>
          {"<div class='remediation'><strong>Recommendation:</strong> " + rec + "</div>" if rec and status_key == "non_compliant" else ""}
        </div>""")
    return "\n".join(cards)


def _missing_cards(missing: list) -> str:
    cards = []
    for m in missing:
        cid = _esc(m.get("ControlId", ""))
        types = ", ".join(m.get("MissingTypes", []))
        cards.append(f'<div class="missing-card"><code>{cid}</code> — Missing: {_esc(types)}</div>')
    return "\n".join(cards)


def _access_denied_cards(access_denied: list[dict] | None) -> str:
    """Render access-denied collector cards."""
    if not access_denied:
        return '<p class="empty">All collectors had sufficient permissions. No access restrictions detected.</p>'
    cards = []
    for ad in access_denied:
        collector = _esc(ad.get("collector", "Unknown"))
        source = _esc(ad.get("source", "Unknown"))
        api = _esc(ad.get("api", "Unknown"))
        status_code = ad.get("status_code", 403)
        cards.append(f"""
        <div class="finding-card" style="border-left:3px solid #F7630C">
          <div class="finding-header">
            <code>{collector}</code>
            <span class="badge" style="background:#F7630C">ACCESS DENIED</span>
            <span class="badge" style="background:#383640">{source}</span>
            <span style="color:var(--text-muted);font-size:11px">HTTP {status_code}</span>
          </div>
          <p class="finding-desc">Your account does not have permission to access <strong>{api}</strong>.
          Data from this collector was skipped. To include this data, ensure your account
          has the required role assignment for this API.</p>
        </div>""")
    return "\n".join(cards)


def _get_css() -> str:
    return """
:root {
  --ms-blue:#0078D4; --ms-green:#107C10; --ms-red:#D13438; --ms-yellow:#FFB900; --ms-orange:#F7630C;
  --primary:#4EA8DE; --success:#54B054; --danger:#E74856; --warning:#FFCB3D; --info:#4FC3F7;
  --bg:#1B1A1F; --bg-elevated:#252429; --bg-card:#22212A; --bg-card-hover:#2A2933;
  --text:#E4E2E0; --text-secondary:#A8A6A3; --text-muted:#918F8C;
  --border:#383640; --border-light:#2E2D35;
  --font-primary:'Segoe UI Variable','Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;
  --font-mono:'Cascadia Code','Fira Code','Consolas',monospace;
  --shadow-sm:0 2px 4px rgba(0,0,0,.2); --shadow-md:0 4px 8px rgba(0,0,0,.24);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font-primary);background:var(--bg);color:var(--text);line-height:1.6}
.layout{display:flex;min-height:100vh}
.sidebar{width:260px;background:#1A1920;border-right:1px solid var(--border-light);padding:24px 0;position:fixed;top:0;bottom:0;overflow-y:auto}
.sidebar-header{padding:0 24px 20px;border-bottom:1px solid var(--border-light)}
.sidebar-header h2{font-size:18px;color:var(--primary)}
.version{font-size:11px;color:var(--text-muted)}
.nav-links{list-style:none;padding:16px 0}
.nav-links li a{display:block;padding:10px 24px;color:var(--text-secondary);text-decoration:none;font-size:14px;transition:all .2s}
.nav-links li a:hover,.nav-links li a.active{color:var(--text);background:rgba(78,168,222,.08);border-left:3px solid var(--primary)}
.sidebar-footer{padding:16px 24px;color:var(--text-muted);font-size:11px;position:absolute;bottom:0}
.content{margin-left:260px;flex:1;padding:32px 40px;max-width:1200px}
.section{margin-bottom:48px}
.page-title{font-size:28px;font-weight:700;margin-bottom:8px}
.meta-bar{display:flex;gap:24px;color:var(--text-secondary);font-size:13px;margin-bottom:24px;flex-wrap:wrap}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;transition:all .2s}
.stat-card:hover{background:var(--bg-card-hover);box-shadow:var(--shadow-md)}
.stat-value{font-size:32px;font-weight:700;font-family:var(--font-mono)}
.stat-label{font-size:12px;color:var(--text-secondary);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
h2{font-size:20px;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border)}
h3{font-size:16px;margin-bottom:12px;color:var(--text-secondary)}
.score-display{display:flex;align-items:center;gap:40px;flex-wrap:wrap}
.ring{filter:drop-shadow(0 0 8px rgba(0,0,0,.3))}
.score-breakdown{display:flex;flex-direction:column;gap:8px}
.score-row{display:flex;align-items:center;gap:8px;font-size:14px}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.severity-summary{margin-top:24px}
.severity-bars{display:flex;flex-direction:column;gap:8px}
.sev-row{display:flex;align-items:center;gap:12px}
.sev-label{width:60px;font-size:12px;text-transform:uppercase;color:var(--text-secondary)}
.sev-track{flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden}
.sev-fill{height:100%;border-radius:4px;transition:width .6s cubic-bezier(.16,1,.3,1)}
.sev-count{width:30px;text-align:right;font-family:var(--font-mono);font-size:13px}
.domain-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.domain-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;transition:all .3s}
.domain-card:hover{transform:translateY(-2px);box-shadow:var(--shadow-md)}
.domain-icon{font-size:28px;margin-bottom:8px}
.domain-name{font-size:13px;color:var(--text-secondary);margin-bottom:4px}
.domain-score{font-size:28px;font-weight:700;font-family:var(--font-mono)}
.domain-detail{font-size:11px;color:var(--text-muted)}
.data-table{width:100%;border-collapse:collapse;font-size:13px}
.data-table th{background:#1E1D24;padding:10px 12px;text-align:left;font-weight:600;border-bottom:2px solid var(--border);color:var(--text-secondary);text-transform:uppercase;font-size:11px;letter-spacing:.5px}
.data-table td{padding:10px 12px;border-bottom:1px solid var(--border-light)}
.data-table tr:hover td{background:var(--bg-card-hover)}
.data-table code{font-family:var(--font-mono);font-size:12px;color:var(--primary)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
.finding-card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;transition:all .2s}
.finding-card:hover{background:var(--bg-card-hover)}
.finding-card.non-compliant{border-left:3px solid var(--ms-red)}
.finding-header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.finding-desc{font-size:14px;color:var(--text)}
.remediation{margin-top:8px;padding:10px;background:#0F2818;border-left:3px solid var(--ms-green);border-radius:4px;font-size:13px;color:#A5D6A7}
.missing-card{background:var(--bg-card);border:1px solid var(--border);border-left:3px solid var(--ms-yellow);border-radius:8px;padding:12px 16px;margin-bottom:8px;font-size:13px}
.missing-card code{color:var(--primary);font-family:var(--font-mono)}
.empty{color:var(--text-muted);font-style:italic}
@media(max-width:768px){.sidebar{display:none}.content{margin-left:0;padding:16px}.stat-grid{grid-template-columns:repeat(2,1fr)}}
@media print{.sidebar,.skip-nav{display:none}.content{margin-left:0}body{background:#fff;color:#000}.stat-card,.finding-card,.domain-card,.missing-card{border:1px solid #ccc;background:#fff}}
.skip-nav{position:absolute;top:-100%;left:16px;padding:12px 24px;background:var(--primary);color:#fff;font-size:14px;font-weight:600;border-radius:0 0 8px 8px;z-index:10000;text-decoration:none;transition:top .2s}
.skip-nav:focus{top:0}
:focus-visible{outline:2px solid var(--primary);outline-offset:2px;border-radius:2px}
button:focus:not(:focus-visible),a:focus:not(:focus-visible){outline:none}
.nav-links li a{min-height:44px;display:flex;align-items:center}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:0.01ms!important;animation-iteration-count:1!important;transition-duration:0.01ms!important;scroll-behavior:auto!important}html{scroll-behavior:auto}}
@media(forced-colors:active){.badge,.stat-card,.finding-card,.domain-card{border:1px solid ButtonText;forced-color-adjust:none}.sidebar{border-right:1px solid ButtonText}.skip-nav:focus{background:Highlight;color:HighlightText}.sev-fill{forced-color-adjust:none}}
"""


def _get_js() -> str:
    return """
document.querySelectorAll('.nav-links a').forEach(function(link){
  link.addEventListener('click',function(){
    document.querySelectorAll('.nav-links a').forEach(function(l){l.classList.remove('active');l.removeAttribute('aria-current')});
    this.classList.add('active');
    this.setAttribute('aria-current','true');
  });
});
// Animate counters
document.querySelectorAll('.stat-value').forEach(function(el){
  var text=el.textContent.trim();
  var match=text.match(/^([\\d,]+)/);
  if(match){
    var target=parseInt(match[1].replace(/,/g,''));
    var dur=1200;var start=0;var startTime=null;
    function animate(ts){
      if(!startTime)startTime=ts;
      var progress=Math.min((ts-startTime)/dur,1);
      var ease=1-Math.pow(1-progress,3);
      var current=Math.round(ease*target);
      el.textContent=text.replace(match[1],current.toLocaleString());
      if(progress<1)requestAnimationFrame(animate);
    }
    requestAnimationFrame(animate);
  }
});
// Table accessibility: add scope attributes
(function(){
  document.querySelectorAll('.data-table thead th').forEach(function(th){if(!th.hasAttribute('scope'))th.setAttribute('scope','col')});
  document.querySelectorAll('.doc-control-table th').forEach(function(th){if(!th.hasAttribute('scope'))th.setAttribute('scope','row')});
})();
"""
