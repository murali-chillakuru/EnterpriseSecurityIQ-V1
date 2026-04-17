"""
Compliance Report — Full HTML
Detailed framework compliance report with resource inventories,
RBAC analysis, Entra details, findings, and remediation roadmap.
Top-nav layout matching AI Agent Security report style.
"""

from __future__ import annotations
import hashlib
import pathlib
from datetime import datetime, timezone
from typing import Any
from app.logger import log
from app.postureiq_reports.shared_theme import (
    esc, get_css, get_js, SEVERITY_COLORS, STATUS_LABELS, DOMAIN_META,
    score_color, severity_badge, status_badge, sev_order, format_ts, format_date,
    format_date_short, humanize_framework, humanize_domain, VERSION,
)
from app.postureiq_reports.inventory import extract_inventory, get_environment_summary


# ── SVG helpers ──────────────────────────────────────────────────────────

def _ring_score_svg(score: float, size: int = 160) -> str:
    """SVG ring chart for compliance score (green=high, red=low)."""
    r = size // 2 - 8
    circ = 2 * 3.14159 * r
    pct = min(score, 100) / 100
    dash = circ * pct
    gap = circ - dash
    cx = cy = size // 2
    color = score_color(score)
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="var(--ring-track)" stroke-width="10"/>'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="10" '
        f'stroke-dasharray="{dash:.2f} {gap:.2f}" stroke-dashoffset="{circ * 0.25:.2f}" '
        f'stroke-linecap="round" style="transition:stroke-dasharray 1s ease"/>'
        f'<text x="{cx}" y="{cy}" text-anchor="middle" dy=".35em" font-size="28" font-weight="700" '
        f'fill="{color}" font-family="var(--font-mono)">{score:.0f}%</text>'
        f'</svg>'
    )


def _donut_svg(slices: list[tuple[str, float, str]], size: int = 140, center_text: str | None = None) -> str:
    """SVG donut chart for severity or status distribution."""
    total = sum(v for _, v, _ in slices) or 1
    r = size // 2 - 4
    circ = 2 * 3.14159 * r
    cx = cy = size // 2
    parts = [f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img">']
    offset = 0
    for label, val, color in slices:
        if val <= 0:
            continue
        dash = circ * (val / total)
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{r * 0.4}" stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})">'
            f'<title>{esc(label)}: {int(val)}</title></circle>'
        )
        offset += dash
    ct = center_text if center_text is not None else str(int(total))
    parts.append(
        f'<text x="{cx}" y="{cy}" text-anchor="middle" dy=".35em" font-size="22" '
        f'font-weight="700" fill="var(--text)" font-family="var(--font-mono)">{esc(ct)}</text></svg>'
    )
    return "".join(parts)


def _bar_chart_svg(items: list[tuple[str, float, str]], width: int = 560) -> str:
    """Horizontal bar chart SVG for domain scores."""
    if not items:
        return ""
    bar_h, gap, lbl_w = 24, 8, 200
    h = len(items) * (bar_h + gap) + gap
    max_val = max(v for _, v, _ in items) or 1
    chart_w = width - lbl_w - 60
    parts = [f'<svg width="{width}" height="{h}" viewBox="0 0 {width} {h}" role="img" style="display:block;margin:auto">']
    for i, (label, val, color) in enumerate(items):
        y = gap + i * (bar_h + gap)
        bw = (val / max_val) * chart_w if max_val else 0
        parts.append(f'<text x="{lbl_w - 8}" y="{y + bar_h // 2 + 4}" text-anchor="end" font-size="11" fill="var(--text-secondary)">{esc(label)}</text>')
        parts.append(f'<rect x="{lbl_w}" y="{y}" width="{bw:.1f}" height="{bar_h}" rx="4" fill="{color}" opacity="0.85"><animate attributeName="width" from="0" to="{bw:.1f}" dur="0.6s" fill="freeze"/></rect>')
        parts.append(f'<text x="{lbl_w + bw + 6}" y="{y + bar_h // 2 + 4}" font-size="11" fill="var(--text)" font-family="var(--font-mono)">{val:.0f}%</text>')
    parts.append("</svg>")
    return "".join(parts)


def _severity_tip(sev: str) -> str:
    tips = {
        "critical": "CRITICAL — highest-impact compliance gap.\\n• Direct security risk, immediate remediation needed\\n• Fix within 0-14 days",
        "high": "HIGH — significant gap requiring prompt attention.\\n• Exploitation possible if combined with other issues\\n• Fix within 0-30 days",
        "medium": "MEDIUM — moderate gap, not immediately exploitable.\\n• Defense-in-depth improvement needed\\n• Fix within 30-90 days",
        "low": "LOW — minor improvement opportunity.\\n• Best-practice recommendation only\\n• Address within 90-180 days",
    }
    return tips.get(sev, "")


# ── Report-specific CSS ──────────────────────────────────────────────────

def _cr_css() -> str:
    """Compliance report CSS: top nav, zoom, tooltips, filter bar."""
    return """
.top-nav{position:sticky;top:0;z-index:500;display:flex;align-items:center;gap:16px;padding:8px 24px;
  background:var(--bg-elevated);border-bottom:1px solid var(--border);font-size:13px;flex-wrap:wrap}
[id],section[id]{scroll-margin-top:56px}
.top-nav .brand{font-weight:700;color:var(--primary);font-size:14px;margin-right:12px}
.top-nav a{color:var(--text-secondary);text-decoration:none;padding:6px 10px;border-radius:6px;transition:all .2s}
.top-nav a:hover{color:var(--text);background:var(--bg-card)}
.nav-dropdown{position:relative}
.nav-dropdown>.nav-toggle{cursor:pointer;user-select:none;padding:6px 10px;border-radius:6px;color:var(--text-secondary);font-size:13px;display:inline-flex;align-items:center;gap:4px;transition:all .2s;min-height:36px;border:none;background:none;font-family:inherit}
.nav-dropdown>.nav-toggle:hover,.nav-dropdown:focus-within>.nav-toggle{color:var(--text);background:var(--bg-card)}
.nav-dropdown>.nav-toggle::after{content:'\\25BE';font-size:10px;margin-left:2px}
.nav-menu{display:none;position:absolute;top:100%;left:0;min-width:220px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.3);padding:6px 0;z-index:600;margin-top:4px;max-height:70vh;overflow-y:auto}
.nav-dropdown:hover>.nav-menu,.nav-dropdown:focus-within>.nav-menu{display:block}
.nav-menu a{display:flex;padding:8px 16px;color:var(--text-secondary);font-size:12px;border-radius:0;min-height:auto;white-space:nowrap}
.nav-menu a:hover{color:var(--text);background:var(--bg-card)}
.nav-menu .nav-sep{height:1px;background:var(--border);margin:4px 12px}
.full-width-content{padding:32px 40px;max-width:1200px;margin:0 auto}
.exec-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin:24px 0}
.exec-panel{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px}
.exec-panel h3{font-size:14px;color:var(--text-secondary);margin-bottom:12px;border:none;padding:0}
.zoom-controls{display:flex;align-items:center;gap:4px;margin-left:auto}
.zoom-controls button{padding:4px 10px;border:1px solid var(--border);border-radius:4px;background:var(--bg-elevated);color:var(--text);cursor:pointer;font-size:14px;min-height:32px;transition:all .2s}
.zoom-controls button:hover{border-color:var(--primary);color:var(--primary)}
#zoom-label{font-family:var(--font-mono);font-size:12px;min-width:42px;text-align:center;color:var(--text-secondary)}
.filter-bar{display:flex;align-items:center;gap:8px;margin-bottom:16px;flex-wrap:wrap;font-size:13px}
.filter-bar input[type="search"]{min-width:240px;padding:8px 12px;border:1px solid var(--border);border-radius:6px;background:var(--bg-elevated);color:var(--text);font-size:13px}
.filter-bar select{padding:8px 12px;border:1px solid var(--border);border-radius:6px;background:var(--bg-elevated);color:var(--text);font-size:13px}
.filter-bar label{font-size:12px;color:var(--text-secondary);font-weight:600}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
#ciq-tooltip{position:fixed;z-index:99999;pointer-events:none;opacity:0;transition:opacity .18s ease;max-width:520px;min-width:220px;padding:14px 18px;
  background:linear-gradient(145deg,var(--bg-elevated),color-mix(in srgb,var(--bg-elevated) 90%,#000));
  color:var(--text);
  border:1.5px solid color-mix(in srgb,var(--primary) 50%,var(--border));
  border-radius:10px;
  font-size:12.5px;line-height:1.6;font-weight:400;text-transform:none;letter-spacing:normal;white-space:normal;
  box-shadow:0 2px 6px rgba(0,0,0,.18),0 8px 24px rgba(0,0,0,.32),0 0 0 1px rgba(255,255,255,.06) inset;
}
#ciq-tooltip.visible{opacity:1}
#ciq-tooltip::before{content:'';position:absolute;width:12px;height:12px;
  background:linear-gradient(145deg,var(--bg-elevated),color-mix(in srgb,var(--bg-elevated) 90%,#000));
  border:1.5px solid color-mix(in srgb,var(--primary) 50%,var(--border));
  transform:rotate(45deg);z-index:-1}
#ciq-tooltip.arrow-bottom::before{bottom:-7px;left:var(--arrow-x,24px);border-top:none;border-left:none}
#ciq-tooltip.arrow-top::before{top:-7px;left:var(--arrow-x,24px);border-bottom:none;border-right:none}
#ciq-tooltip .tip-label{font-weight:600;color:var(--primary)}
/* Table reading guide */
.table-guide{padding:14px 18px;border-radius:8px;border-left:4px solid var(--primary);background:color-mix(in srgb,var(--primary) 6%,var(--bg-card));margin-bottom:16px;font-size:12.5px;line-height:1.7;color:var(--text-secondary)}
.table-guide strong{color:var(--text)}
.table-guide .guide-cols{display:flex;flex-wrap:wrap;gap:16px;margin-top:8px}
.table-guide .guide-col{flex:1;min-width:200px}
/* Access-denied info banner */
.access-info{padding:12px 16px;border-radius:8px;border-left:4px solid var(--ms-orange);background:color-mix(in srgb,var(--ms-orange) 8%,var(--bg-card));margin-bottom:16px;font-size:13px;line-height:1.6}
.access-info strong{color:var(--ms-orange)}
/* Subscription collapsible sections */
.sub-controls{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.sub-controls button{padding:6px 14px;border:1px solid var(--border);border-radius:6px;background:var(--bg-elevated);color:var(--text-secondary);cursor:pointer;font-size:12px;transition:all .2s}
.sub-controls button:hover{border-color:var(--primary);color:var(--primary)}
details.sub-section{border:1px solid var(--border);border-radius:8px;margin-bottom:12px;overflow:hidden}
details.sub-section>summary{padding:12px 16px;background:var(--bg-card);cursor:pointer;font-weight:600;font-size:14px;list-style:none;display:flex;align-items:center;gap:8px;user-select:none}
details.sub-section>summary::-webkit-details-marker{display:none}
details.sub-section>summary::before{content:'\\25B6';font-size:10px;transition:transform .2s;color:var(--text-muted)}
details.sub-section[open]>summary::before{transform:rotate(90deg)}
details.sub-section>.sub-content{padding:16px}
/* Resource compliance table — fixed layout with column widths to prevent overflow */
#resource-compliance-table{table-layout:fixed}
#resource-compliance-table th:nth-child(1){width:14%}
#resource-compliance-table th:nth-child(2){width:12%}
#resource-compliance-table th:nth-child(3){width:8%}
#resource-compliance-table th:nth-child(4){width:8%}
#resource-compliance-table th:nth-child(5){width:6%}
#resource-compliance-table th:nth-child(6){width:26%}
#resource-compliance-table th:nth-child(7){width:26%}
#resource-compliance-table td{word-break:break-word;overflow-wrap:break-word}
@media(max-width:768px){.full-width-content{padding:16px}.exec-grid{grid-template-columns:1fr}.filter-bar{flex-direction:column;align-items:stretch}.table-guide .guide-cols{flex-direction:column}}
@media print{.top-nav,.filter-bar,.zoom-controls,.back-to-top,.skip-nav{display:none!important}.full-width-content{padding:16px;max-width:100%}body{background:#fff;color:#000;font-size:12px}}
"""


def _cr_js() -> str:
    """Compliance report JS: zoom, finding filter, tooltip engine."""
    return r"""
// Zoom
var zoomLevel=100;
function zoomIn(){zoomLevel=Math.min(zoomLevel+10,150);applyZoom()}
function zoomOut(){zoomLevel=Math.max(zoomLevel-10,70);applyZoom()}
function zoomReset(){zoomLevel=100;applyZoom()}
function applyZoom(){document.querySelector('.full-width-content').style.zoom=(zoomLevel/100);document.getElementById('zoom-label').textContent=zoomLevel+'%'}

// Unified control/findings filter
function filterControls(){
  var q=(document.getElementById('control-search').value||'').toLowerCase();
  var sev=(document.getElementById('filter-severity').value||'').toLowerCase();
  var dom=(document.getElementById('filter-domain').value||'').toLowerCase();
  var st=(document.getElementById('filter-status').value||'').toLowerCase();
  var shown=0;
  document.querySelectorAll('#control-results-table tbody tr').forEach(function(row){
    var match=true;
    if(q&&row.textContent.toLowerCase().indexOf(q)<0)match=false;
    if(sev&&row.getAttribute('data-severity')!==sev)match=false;
    if(dom&&row.getAttribute('data-domain')!==dom)match=false;
    if(st&&row.getAttribute('data-status')!==st)match=false;
    row.style.display=match?'':'none';
    if(match)shown++;
  });
  var hdr=document.getElementById('controls-heading');
  if(hdr)hdr.textContent='5.3 Control Results ('+shown+')';
}

// Resource table filter
function filterResourceTable(){
  var input=document.getElementById('resource-search').value.toLowerCase();
  var rows=document.querySelectorAll('#resource-compliance-table tbody tr');
  rows.forEach(function(row){row.style.display=row.textContent.toLowerCase().includes(input)?'':'none'});
}

// Expand/Collapse all subscription sections (scoped to parent section)
function toggleSubs(btn,open){var sec=btn.closest('.section')||btn.closest('section');if(!sec)sec=document.body;sec.querySelectorAll('details.sub-section').forEach(function(d){d.open=open})}

// Tooltip engine (viewport-aware)
(function(){
  var tip=document.getElementById('ciq-tooltip');
  if(!tip)return;
  var GAP=10,MARGIN=12;
  function show(ev){
    var tgt=ev.target.closest('[data-tip]');
    if(!tgt)return;
    var text=tgt.getAttribute('data-tip');
    if(!text)return;
    var d=document.createElement('span');d.textContent=text;var safe=d.innerHTML;
    safe=safe.replace(/\\n/g,'<br>');
    safe=safe.replace(/<br>\u2022 /g,'</p><p style="margin:2px 0 2px 12px;text-indent:-10px">\u2022 ');
    safe=safe.replace(/(Checks:|Evaluates:|Details:)/g,'<span class="tip-label">$1</span>');
    tip.innerHTML=safe;
    tip.classList.add('visible');
    requestAnimationFrame(function(){
      var r=tgt.getBoundingClientRect();
      var tw=tip.offsetWidth,th=tip.offsetHeight;
      var vw=window.innerWidth,vh=window.innerHeight;
      var above=r.top-GAP-th;
      var below=r.bottom+GAP;
      var top,arrow;
      if(above>=MARGIN){top=above;arrow='arrow-bottom';}
      else if(below+th<=vh-MARGIN){top=below;arrow='arrow-top';}
      else{top=Math.max(MARGIN,vh-th-MARGIN);arrow='';}
      var left=r.left+r.width/2-tw/2;
      left=Math.max(MARGIN,Math.min(left,vw-tw-MARGIN));
      var arrowX=r.left+r.width/2-left;
      arrowX=Math.max(16,Math.min(arrowX,tw-16));
      tip.style.top=top+'px';
      tip.style.left=left+'px';
      tip.style.setProperty('--arrow-x',arrowX+'px');
      tip.className='visible'+(arrow?' '+arrow:'');
    });
  }
  function hide(){tip.classList.remove('visible');tip.className='';}
  document.addEventListener('mouseenter',show,true);
  document.addEventListener('mouseleave',function(ev){if(ev.target.closest('[data-tip]'))hide();},true);
  document.addEventListener('focusin',show,true);
  document.addEventListener('focusout',function(ev){if(ev.target.closest('[data-tip]'))hide();},true);
})();

// SHA-256 report hash
(function(){
  var el=document.getElementById('report-hash');
  if(!el||typeof crypto==='undefined'||!crypto.subtle)return;
  var html=document.documentElement.outerHTML;
  var buf=new TextEncoder().encode(html);
  crypto.subtle.digest('SHA-256',buf).then(function(h){
    var a=Array.from(new Uint8Array(h));
    el.textContent=a.map(function(b){return b.toString(16).padStart(2,'0')}).join('');
  });
})();


"""


def generate_postureiq_report_html(
    results: dict[str, Any],
    evidence: list[dict],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    """Generate the full PostureIQ report HTML and return the file path."""
    if not results:
        raise ValueError("Cannot generate HTML report: results dict is empty")

    ts = datetime.now(timezone.utc)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    inv = extract_inventory(evidence)
    env_summary = get_environment_summary(inv)

    summary = results.get("summary", {})
    controls = results.get("control_results", [])
    findings = results.get("findings", [])
    missing = results.get("missing_evidence", [])
    domain_scores = summary.get("DomainScores", {})
    tenant = tenant_info or {}

    score = summary.get("ComplianceScore", 0)
    sc = score_color(score)
    frameworks = summary.get("Frameworks", ["FedRAMP"])
    fw_label = ", ".join(humanize_framework(fw) for fw in frameworks)

    # Use framework-specific file name for clarity
    fw_prefix = frameworks[0].lower().replace(" ", "-") if len(frameworks) == 1 else "compliance"
    path = out / f"{fw_prefix}-compliance-report.html"
    report_id = f"CIQ-{ts.strftime('%Y%m%d-%H%M%S')}"

    n_compliant = summary.get("Compliant", 0)
    n_nc = summary.get("NonCompliant", 0)
    n_partial = summary.get("Partial", 0)
    n_missing_ev = summary.get("MissingEvidence", 0)
    n_crit = summary.get("CriticalFindings", 0)
    n_high = summary.get("HighFindings", 0)
    n_med = summary.get("MediumFindings", 0)
    total_controls = summary.get("TotalControls", 0)
    total_evidence = summary.get("TotalEvidence", 0)

    # SVG charts
    ring_svg = _ring_score_svg(score, 160)
    status_donut = _donut_svg([
        ("Compliant", n_compliant, "#107C10"),
        ("Non-Compliant", n_nc, "#D13438"),
        ("Partial", n_partial, "#FFB900"),
        ("Missing Evidence", n_missing_ev, "#A8A6A3"),
    ], 140, f"{total_controls}")
    # Severity bars for exec panel
    max_sev = max(n_crit, n_high, n_med, 1)
    sev_bars = ""
    for name, count, color in [("Critical", n_crit, "#D13438"), ("High", n_high, "#F7630C"), ("Medium", n_med, "#FFB900")]:
        pct = (count / max_sev) * 100 if max_sev > 0 else 0
        sev_bars += (
            f'<div class="sev-row"><span class="sev-label" data-tip="{name} severity: {count} non-compliant finding{"s" if count != 1 else ""}">{name}</span>'
            f'<div class="sev-track"><div class="sev-fill" style="width:{pct:.0f}%;background:{color}"></div></div>'
            f'<span class="sev-count">{count}</span></div>'
        )

    # Build domain dropdown entries for filter
    domain_options = ""
    for d_key in domain_scores:
        meta = DOMAIN_META.get(d_key, {"name": d_key.replace("_", " ").title()})
        domain_options += f'<option value="{esc(d_key)}">{esc(meta["name"])}</option>'

    # Pre-compute to avoid f-string nesting issues in Python 3.12+
    fw_summaries = summary.get("FrameworkSummaries", {})
    fw_cards_html = _framework_cards(fw_summaries)
    control_rows_html = _control_rows(controls, findings)
    resource_compliance_html = _resource_compliance_table(findings)
    remediation_html = _remediation_plan(findings, access_denied)
    evidence_gaps_html = _evidence_gaps(missing, access_denied)
    entra_roles_html = _entra_roles_table(inv['entra_roles'], inv.get('entra_role_members', []), access_denied)
    entra_apps_html = _applications_table(inv['entra_applications'], inv['entra_service_principals'])
    azure_inventory_html = _azure_inventory_section(inv)

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>PostureIQ &mdash; {esc(fw_label)} Compliance Assessment Report</title>
<style>{get_css()}{_cr_css()}</style>
</head>
<body>
<a href="#main" class="skip-nav">Skip to content</a>

<nav class="top-nav" aria-label="Report sections">
  <span class="brand" data-tip="PostureIQ compliance assessment report.\\n• Automated evaluation against security and compliance frameworks\\n• Covers Azure resources and Microsoft Entra ID\\n• Read-only: no changes are made to your environment">&#128737; PostureIQ</span>
  <div class="nav-dropdown">
    <button class="nav-toggle" data-tip="Report metadata, confidentiality notice, and audit attestation.">Document</button>
    <div class="nav-menu">
      <a href="#doc-control" data-tip="Report ID, scope, classification, and data integrity.">Report Metadata</a>
      <a href="#doc-control" data-tip="Attestation of read-only data collection." onclick="setTimeout(function(){{document.querySelector('#doc-control h3').scrollIntoView({{behavior:'smooth'}})}},50)">Audit Attestation</a>
    </div>
  </div>
  <a href="#exec-summary" data-tip="Compliance score, severity distribution, and assessed environment summary.">Summary</a>
  <div class="nav-dropdown">
    <button class="nav-toggle" data-tip="Azure and Entra ID resource inventories.">Inventory</button>
    <div class="nav-menu">
      <a href="#azure-inventory">Azure Resources</a>
      <a href="#entra-inventory">Entra ID</a>
    </div>
  </div>
  <div class="nav-dropdown">
    <button class="nav-toggle" data-tip="Framework scores, domain analysis, control results, and findings.">Compliance</button>
    <div class="nav-menu">
      <a href="#compliance-results">Framework &amp; Domain Overview</a>
      <a href="#controls">Control Results ({len(controls)})</a>
      <a href="#resource-compliance">Resource Details</a>
    </div>
  </div>
  <div class="nav-dropdown">
    <button class="nav-toggle" data-tip="Remediation plan and evidence gaps.">Actions</button>
    <div class="nav-menu">
      <a href="#remediation">Remediation Plan</a>
      <a href="#evidence-gaps">Evidence Gaps</a>
    </div>
  </div>
  <div class="zoom-controls" aria-label="Page zoom">
    <button onclick="zoomOut()" aria-label="Zoom out" data-tip="Decrease page zoom by 10%.">&minus;</button>
    <span id="zoom-label">100%</span>
    <button onclick="zoomIn()" aria-label="Zoom in" data-tip="Increase page zoom by 10%.">&plus;</button>
    <button onclick="zoomReset()" aria-label="Reset zoom" data-tip="Reset zoom to 100%." style="font-size:11px">Reset</button>
  </div>
  <button class="theme-btn" onclick="toggleTheme()" style="margin:0;padding:6px 14px"
          aria-label="Toggle dark and light theme" data-tip="Switch between dark and light viewing mode.">Switch to Light</button>
</nav>

<main id="main" class="full-width-content">

    <!-- Document Control -->
    <section id="doc-control" class="section">
      <h1 class="page-title">PostureIQ &mdash; {esc(fw_label)} Compliance Assessment Report</h1>
      <table class="doc-control-table">
        <tr><th data-tip="Unique identifier for this report.\\n• Use in audit trails and remediation tickets\\n• Ensures all stakeholders reference the same assessment">Report Identifier</th><td>{esc(report_id)}</td></tr>
        <tr><th data-tip="Assessment module that produced this report.\\n• {esc(fw_label)} compliance evaluation\\n• Covers {total_controls} security controls">Assessment Name</th><td>PostureIQ {esc(fw_label)} Assessment</td></tr>
        <tr><th data-tip="When this report was generated.\\n• Point-in-time snapshot\\n• Re-run assessment to capture current state">Date Generated</th><td>{format_ts(ts)}</td></tr>
        <tr><th data-tip="Microsoft Entra ID tenant that was assessed.\\n• Verify this matches your intended target">Tenant ID</th><td><code>{esc(tenant.get('TenantId', tenant.get('tenant_id', 'N/A')))}</code></td></tr>
        <tr><th data-tip="Display name of the Entra ID tenant.\\n• Retrieved from Microsoft Graph API">Tenant Name</th><td>{esc(tenant.get('DisplayName', tenant.get('display_name', 'Unknown')))}</td></tr>
        <tr><th data-tip="Compliance frameworks evaluated in this assessment.\\n• Each framework maps to a set of security controls">Frameworks Evaluated</th><td>{esc(fw_label)}</td></tr>
        <tr><th data-tip="Data classification level for this report.\\n• Contains sensitive resource IDs and vulnerability details\\n• Restrict distribution to authorized personnel">Classification</th><td>CONFIDENTIAL &mdash; Authorized Recipients Only</td></tr>
        <tr><th data-tip="Tool version that produced this report.\\n• Version tracking ensures reproducibility">Tool</th><td>PostureIQ AI Agent v{VERSION}</td></tr>
        <tr><th data-tip="How evidence was collected from your environment.\\n• All calls are read-only (GET only)\\n• No tenant modifications made">Collection Method</th><td>Azure Resource Manager API + Microsoft Graph API (Read-Only)</td></tr>
      </table>
      <div class="conf-notice">
        <strong>CONFIDENTIALITY NOTICE:</strong> This document contains sensitive security and compliance
        information about the assessed environment. Distribution is restricted to authorized personnel only.
      </div>
      <h3>Audit Attestation</h3>
      <table class="doc-control-table">
        <tr><th data-tip="Scope of this security assessment.\\n• Control-plane configuration review\\n• No data-plane analysis">Assessment Scope</th><td>Control-plane configuration review of Azure and Microsoft Entra ID resources</td></tr>
        <tr><th data-tip="Data integrity confirmation.\\n• Read-only API calls only\\n• No write, delete, or update operations">Data Integrity</th><td>All evidence collected via read-only API calls; no tenant modifications were made</td></tr>
        <tr><th data-tip="Total configuration records gathered.\\n• Each record = one API response evaluated\\n• More records = broader coverage">Evidence Records</th><td>{total_evidence:,} records collected and evaluated</td></tr>
        <tr><th data-tip="Tamper detection hash.\\n• SHA-256 of the complete report HTML\\n• Computed client-side at render time\\n• Save for audit defensibility">Report Hash (SHA-256)</th><td><code id="report-hash">Computed at render</code></td></tr>
        <tr><th data-tip="When evidence was collected.\\n• Point-in-time snapshot\\n• Changes after this date are NOT reflected">Assessment Period</th><td>{format_date_short(ts)} (point-in-time snapshot)</td></tr>
      </table>
    </section>

    <!-- Table of Contents (compact) -->
    <section id="toc" class="section" style="padding:12px 24px">
      <div class="toc-grid" style="font-size:13px">
        <a href="#exec-summary" class="toc-link"><span class="toc-num">1.</span> Executive Summary</a>
        <a href="#scope" class="toc-link"><span class="toc-num">2.</span> Scope &amp; Methodology</a>
        <a href="#azure-inventory" class="toc-link"><span class="toc-num">3.</span> Azure Inventory</a>
        <a href="#entra-inventory" class="toc-link"><span class="toc-num">4.</span> Entra ID Inventory</a>
        <a href="#compliance-results" class="toc-link"><span class="toc-num">5.</span> Compliance Results</a>
        <a href="#resource-compliance" class="toc-link"><span class="toc-num">6.</span> Resource Details</a>
        <a href="#remediation" class="toc-link"><span class="toc-num">7.</span> Remediation Plan</a>
        <a href="#evidence-gaps" class="toc-link"><span class="toc-num">8.</span> Evidence Gaps</a>
      </div>
    </section>

    <!-- Executive Summary -->
    <section id="exec-summary" class="section">
      <h2>1. Executive Summary</h2>
      <p style="margin-bottom:16px;color:var(--text-secondary);line-height:1.6;max-width:960px">
        Compliance assessment results for tenant
        <code>{esc(tenant.get('TenantId', tenant.get('tenant_id', '')))}</code> evaluated against the
        <strong>{esc(fw_label)}</strong> compliance framework(s).
      </p>

      <div class="stat-grid">
        <div class="stat-card" data-tip="Overall compliance score.\\n• {n_compliant} of {total_controls} controls are compliant\\n• Score = (Compliant / Total) &times; 100\\n• Target: 80%+ for production readiness" tabindex="0"><div class="stat-value" style="color:{sc}">{score:.1f}%</div><div class="stat-label">Compliance Score</div></div>
        <div class="stat-card" data-tip="Total security controls evaluated.\\n• Each control maps to a specific compliance requirement\\n• Controls are grouped by domain (access, identity, data, etc.)" tabindex="0"><div class="stat-value">{total_controls}</div><div class="stat-label">Total Controls</div></div>
        <div class="stat-card" data-tip="Controls that fully meet the compliance requirement.\\n• {n_compliant} of {total_controls} ({n_compliant*100//max(total_controls,1)}%)\\n• Green = good configuration detected" tabindex="0"><div class="stat-value" style="color:#107C10">{n_compliant}</div><div class="stat-label">Compliant</div></div>
        <div class="stat-card" data-tip="Controls that DO NOT meet the requirement.\\n• {n_nc} non-compliant controls detected\\n• Each generates one or more findings\\n• See Findings section for details and remediation" tabindex="0"><div class="stat-value" style="color:#D13438">{n_nc}</div><div class="stat-label">Non-Compliant</div></div>
        <div class="stat-card" data-tip="Controls where evidence could not be collected.\\n• {n_missing_ev} controls have missing evidence\\n• May indicate missing permissions or unconfigured features\\n• See Missing Evidence section for resolution steps" tabindex="0"><div class="stat-value" style="color:#A8A6A3">{n_missing_ev}</div><div class="stat-label">Missing Evidence</div></div>
        <div class="stat-card" data-tip="Total API responses evaluated.\\n• {total_evidence:,} evidence records\\n• Includes Azure resources, Entra objects, policies, and configurations" tabindex="0"><div class="stat-value">{total_evidence:,}</div><div class="stat-label">Evidence Records</div></div>
      </div>

      <div class="exec-grid">
        <div class="exec-panel" data-tip="Ring chart showing overall compliance score.\\n• Green (&ge;80%) = Strong posture\\n• Yellow (60-79%) = Moderate gaps\\n• Red (&lt;60%) = Significant remediation needed">
          <h3>Compliance Score</h3>
          <div class="score-display" style="justify-content:center">{ring_svg}</div>
          <div style="display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin-top:10px;font-size:11px;color:var(--text-secondary)">
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#107C10;vertical-align:middle"></span> &ge;80%</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#FFB900;vertical-align:middle"></span> 60-79%</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#D13438;vertical-align:middle"></span> &lt;60%</span>
          </div>
        </div>
        <div class="exec-panel" data-tip="Donut chart showing control status distribution.\\n• Green = Compliant ({n_compliant})\\n• Red = Non-Compliant ({n_nc})\\n• Yellow = Partial ({n_partial})\\n• Gray = Missing Evidence ({n_missing_ev})">
          <h3>Control Status Distribution</h3>
          <div style="text-align:center">{status_donut}</div>
          <div style="display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin-top:10px;font-size:11px;color:var(--text-secondary)">
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#107C10;vertical-align:middle"></span> Compliant ({n_compliant})</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#D13438;vertical-align:middle"></span> Non-Compliant ({n_nc})</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#FFB900;vertical-align:middle"></span> Partial ({n_partial})</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#A8A6A3;vertical-align:middle"></span> Missing ({n_missing_ev})</span>
          </div>
        </div>
        <div class="exec-panel" data-tip="Non-compliant findings by severity level.\\n• Critical: {n_crit}, High: {n_high}, Medium: {n_med}\\n• Bar width proportional to count">
          <h3>Non-Compliant by Severity</h3>
          <div class="sev-bars">{sev_bars}</div>
        </div>
      </div>

      <h3>Assessed Environment Summary</h3>
      <table class="data-table">
        <thead><tr><th>Resource Category</th><th>Count</th></tr></thead>
        <tbody>
          {"".join(f'<tr><td>{esc(k)}</td><td>{v:,}</td></tr>' for k, v in env_summary.items())}
        </tbody>
      </table>

      <h3>Risk Category Definitions</h3>
      <div class="risk-def" style="border-left:3px solid #D13438">
        <h4 style="color:#D13438">HIGH (Critical, High)</h4>
        <p>Direct security impact with immediate exploitation potential. Missing fundamental controls (MFA, excessive privileges, absent encryption). <strong>Remediation: 0-30 days.</strong></p>
      </div>
      <div class="risk-def" style="border-left:3px solid #FFB900">
        <h4 style="color:#FFB900">MEDIUM</h4>
        <p>Configuration gaps exploitable under certain conditions. Incomplete defense-in-depth. <strong>Remediation: 30-90 days.</strong></p>
      </div>
      <div class="risk-def" style="border-left:3px solid #107C10">
        <h4 style="color:#107C10">LOW</h4>
        <p>Best-practice deviations with minimal direct security impact. <strong>Remediation: 90-180 days.</strong></p>
      </div>
    </section>

    <!-- Scope & Methodology -->
    <section id="scope" class="section">
      <h2>2. Assessment Scope &amp; Methodology</h2>
      <h3>2.1 Scope</h3>
      <p>This assessment covers control-plane configurations of:</p>
      <ul style="margin:8px 0 16px 24px;color:var(--text-secondary)">
        <li><strong>Azure Resources:</strong> All accessible subscriptions, resource groups, resources, RBAC assignments,
        policy assignments, and diagnostic settings across {len(inv['subscriptions'])} subscription(s).</li>
        <li><strong>Microsoft Entra ID:</strong> Tenant configuration, directory roles, conditional access policies,
        application registrations, service principals, and user/group demographics.</li>
      </ul>
      <h3>2.2 Methodology</h3>
      <p>PostureIQ AI Agent v{VERSION} performs the following pipeline:</p>
      <ol style="margin:8px 0 16px 24px;color:var(--text-secondary)">
        <li><strong>Evidence Collection</strong> &mdash; Read-only calls to Azure Resource Manager and Microsoft Graph APIs.</li>
        <li><strong>Normalization</strong> &mdash; Collected data transformed into standardized evidence records.</li>
        <li><strong>Evaluation</strong> &mdash; Evidence mapped to compliance framework controls and evaluated.</li>
        <li><strong>Reporting</strong> &mdash; Findings generated with severity ratings and remediation guidance.</li>
      </ol>
      <div class="conf-notice">
        <strong>Important Limitations:</strong> This assessment evaluates control-plane configurations only.
        Data-plane analysis is outside scope. No tenant resources were created, modified, or deleted.
      </div>
    </section>

    <!-- Azure Resource Inventory -->
    <section id="azure-inventory" class="section">
      <h2>3. Azure Resource Inventory</h2>
      {azure_inventory_html}
    </section>

    <!-- Entra ID Inventory -->
    <section id="entra-inventory" class="section">
      <h2>4. Microsoft Entra ID Resource Inventory</h2>
      <div class="sub-controls">
        <button onclick="toggleSubs(this,true)">Expand All</button>
        <button onclick="toggleSubs(this,false)">Collapse All</button>
      </div>
      <details class="sub-section">
        <summary>4.1 Tenant Information</summary>
        <div class="sub-content">{_tenant_info_table(inv['entra_tenant'])}</div>
      </details>
      <details class="sub-section">
        <summary>4.2 Directory Roles</summary>
        <div class="sub-content">{entra_roles_html}</div>
      </details>
      <details class="sub-section">
        <summary>4.3 Conditional Access Policies ({len(inv['entra_ca_policies'])} policies)</summary>
        <div class="sub-content">{_ca_policies_table(inv['entra_ca_policies'])}</div>
      </details>
      <details class="sub-section">
        <summary>4.4 Applications ({len(inv['entra_applications'])} registrations, {len(inv['entra_service_principals'])} service principals)</summary>
        <div class="sub-content">{entra_apps_html}</div>
      </details>
      {_users_summary(inv['entra_users_summary'], inv['entra_mfa_summary'])}
    </section>

    <!-- Compliance Results (merged: frameworks + domains + controls) -->
    <section id="compliance-results" class="section">
      <h2>5. Compliance Results</h2>
      <h3 id="frameworks">5.1 Framework Summary</h3>
      {fw_cards_html}
      <h3 id="domains" style="margin-top:32px">5.2 Domain Analysis</h3>
      <div class="domain-grid">
        {_domain_cards(domain_scores)}
      </div>
      <h3 id="controls" style="margin-top:32px"><span id="controls-heading">5.3 Control Results ({len(controls)})</span></h3>
      <div class="filter-bar" role="search" aria-label="Filter controls">
        <label for="control-search">Search:</label>
        <input id="control-search" type="search" placeholder="Search controls&hellip;" oninput="filterControls()">
        <label for="filter-severity">Severity:</label>
        <select id="filter-severity" onchange="filterControls()">
          <option value="">All</option>
          <option value="critical">Critical</option><option value="high">High</option>
          <option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <label for="filter-domain">Domain:</label>
        <select id="filter-domain" onchange="filterControls()">
          <option value="">All</option>{domain_options}
        </select>
        <label for="filter-status">Status:</label>
        <select id="filter-status" onchange="filterControls()">
          <option value="">All</option>
          <option value="non_compliant">Non-Compliant</option>
          <option value="partial">Partial</option>
          <option value="compliant">Compliant</option>
          <option value="missing_evidence">Missing Evidence</option>
        </select>
      </div>
      <div class="table-guide">
        <strong>How to read this table:</strong> Each row is a security control evaluated against the framework. Use the filters above to narrow results.
        <div class="guide-cols">
          <div class="guide-col"><strong>Severity</strong> indicates risk impact (Critical &gt; High &gt; Medium &gt; Low). <strong>Status</strong> shows the evaluation result.</div>
          <div class="guide-col"><strong>Description</strong> previews the primary observation. <strong>Findings</strong> counts distinct observations; <strong>Resources</strong> shows affected resources. Non-compliant controls have guidance in Section 7.</div>
        </div>
      </div>
      <table class="data-table" id="control-results-table">
        <thead><tr><th>Control</th><th>Title</th><th>Framework</th><th>Domain</th><th>Severity</th><th>Status</th><th>Description</th><th>Findings</th><th>Resources</th></tr></thead>
        <tbody>{control_rows_html}</tbody>
      </table>
    </section>

    <!-- Resource Compliance Details -->
    <section id="resource-compliance" class="section">
      <h2>6. Resource-Level Compliance Details</h2>
      <p style="margin-bottom:12px;color:var(--text-secondary)">Per-resource compliance status extracted from evaluation findings. Use the search box to filter by resource name, type, or status.</p>
      {resource_compliance_html}
    </section>

    <!-- Remediation Plan -->
    <section id="remediation" class="section">
      <h2>7. Remediation Plan</h2>
      {remediation_html}
    </section>

    <!-- Evidence Gaps -->
    <section id="evidence-gaps" class="section">
      <h2>8. Evidence Gaps</h2>
      {evidence_gaps_html}
    </section>

    <footer style="text-align:center;color:var(--text-muted);font-size:12px;padding:32px 0;border-top:1px solid var(--border)">
      Generated by PostureIQ AI Agent v{VERSION} &mdash; {format_date_short(ts)} &mdash; CONFIDENTIAL
    </footer>

</main>

<div id="ciq-tooltip" role="tooltip" aria-hidden="true"></div>
<button class="back-to-top" aria-label="Back to top" data-tip="Scroll back to the top of the report.">&#8593;</button>

<script>{get_js()}</script>
<script>{_cr_js()}</script>
</body>
</html>"""

    # Compute hash, inject, write once
    report_hash = hashlib.sha256(html.encode("utf-8")).hexdigest()
    html = html.replace("Computed at render", report_hash)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    log.info("Compliance report HTML: %s", path)
    return str(path)



# ── Table builders ───────────────────────────────────────────────────────


def _azure_inventory_section(inv: dict) -> str:
    """Build Section 3 with per-subscription collapsible details, Expand/Collapse All."""
    subs = inv["subscriptions"]
    rgs = inv["resource_groups"]
    resources = inv["resources"]
    rbac = inv["rbac_assignments"]
    privileged = inv["privileged_assignments"]
    owners = inv["owner_assignments"]
    policies = inv["policy_assignments"]

    parts: list[str] = []

    # Section-level expand/collapse controls (scoped to this section)
    parts.append(
        '<div class="sub-controls">'
        '<button onclick="toggleSubs(this,true)">Expand All</button>'
        '<button onclick="toggleSubs(this,false)">Collapse All</button>'
        '</div>'
    )

    # Summary table
    parts.append(
        f'<details class="sub-section">'
        f'<summary>3.1 Subscriptions ({len(subs)} total)</summary>'
        f'<div class="sub-content">{_subscriptions_table(subs)}</div>'
        f'</details>'
    )

    # Overall resource type distribution
    parts.append(
        f'<details class="sub-section">'
        f'<summary>3.2 Resource Type Distribution ({len(resources)} resources total)</summary>'
        f'<div class="sub-content">{_resource_type_table(inv["resource_type_counts"])}</div>'
        f'</details>'
    )

    # Per-subscription details (wrapped in a details section like 3.1 and 3.2)
    sub_details_parts: list[str] = []

    for sub in subs:
        sub_id = sub.get("SubscriptionId", "")
        sub_name = esc(sub.get("SubscriptionName", sub_id))

        # Filter data for this subscription
        sub_rgs = [r for r in rgs if r.get("SubscriptionId", "") == sub_id or r.get("SubscriptionName", "") == sub_name]
        sub_res = [r for r in resources if r.get("SubscriptionId", "") == sub_id or r.get("SubscriptionName", "") == sub_name]
        sub_rbac = [r for r in rbac if r.get("SubscriptionId", "") == sub_id or r.get("SubscriptionName", "") == sub_name]
        sub_priv = [r for r in privileged if r.get("SubscriptionId", "") == sub_id or r.get("SubscriptionName", "") == sub_name]
        sub_owners = [r for r in owners if r.get("SubscriptionId", "") == sub_id or r.get("SubscriptionName", "") == sub_name]
        sub_policies = [r for r in policies if r.get("SubscriptionId", "") == sub_id or r.get("SubscriptionName", "") == sub_name or sub_id in r.get("Scope", "")]

        # Count resource types for this sub
        sub_type_counts: dict[str, int] = {}
        for r in sub_res:
            rt = r.get("ResourceType") or r.get("Type") or r.get("type", "Unknown")
            sub_type_counts[rt] = sub_type_counts.get(rt, 0) + 1

        summary_stats = (
            f'{len(sub_rgs)} resource groups, {len(sub_res)} resources, '
            f'{len(sub_rbac)} RBAC assignments ({len(sub_priv)} privileged, {len(sub_owners)} owners), '
            f'{len(sub_policies)} policies'
        )

        content_parts: list[str] = []
        content_parts.append(f'<h4>Resource Groups ({len(sub_rgs)})</h4>')
        content_parts.append(_resource_groups_table(sub_rgs) if sub_rgs else '<p class="empty">No resource groups.</p>')
        content_parts.append(f'<h4>Resources by Type ({len(sub_res)})</h4>')
        content_parts.append(_resource_type_table(sub_type_counts) if sub_type_counts else '<p class="empty">No resources.</p>')
        content_parts.append(f'<h4>Privileged Role Assignments ({len(sub_priv)})</h4>')
        content_parts.append(_rbac_table(sub_priv) if sub_priv else '<p class="empty">No privileged assignments.</p>')
        content_parts.append(f'<h4>Policy Assignments ({len(sub_policies)})</h4>')
        content_parts.append(_policy_table(sub_policies) if sub_policies else '<p class="empty">No policy assignments.</p>')

        sub_details_parts.append(
            f'<details class="sub-section">'
            f'<summary>{sub_name} <span style="font-weight:400;font-size:12px;color:var(--text-muted)">'
            f'&mdash; {summary_stats}</span></summary>'
            f'<div class="sub-content">{"".join(content_parts)}</div>'
            f'</details>'
        )

    parts.append(
        f'<details class="sub-section">'
        f'<summary>3.3 Per-Subscription Details ({len(subs)} subscriptions)</summary>'
        f'<div class="sub-content">{"".join(sub_details_parts)}</div>'
        f'</details>'
    )

    # Cross-subscription totals
    totals_table = (
        f'<table class="data-table"><thead><tr><th>Metric</th><th>Total</th></tr></thead><tbody>'
        f'<tr><td>Resource Groups</td><td>{len(rgs)}</td></tr>'
        f'<tr><td>Resources</td><td>{len(resources)}</td></tr>'
        f'<tr><td>RBAC Assignments</td><td>{len(rbac)}</td></tr>'
        f'<tr><td>Privileged Assignments</td><td>{len(privileged)}</td></tr>'
        f'<tr><td>Owner Assignments</td><td>{len(owners)}</td></tr>'
        f'<tr><td>Policy Assignments</td><td>{len(policies)}</td></tr>'
        f'</tbody></table>'
    )
    parts.append(
        f'<details class="sub-section">'
        f'<summary>3.4 Cross-Subscription Totals</summary>'
        f'<div class="sub-content">{totals_table}</div>'
        f'</details>'
    )

    return "\n".join(parts)


def _subscriptions_table(subs: list[dict]) -> str:
    if not subs:
        return '<p class="empty">No subscriptions discovered.</p>'
    rows = "".join(
        f'<tr><td><code>{esc(s.get("SubscriptionId", ""))}</code></td>'
        f'<td>{esc(s.get("SubscriptionName", ""))}</td>'
        f'<td>{esc(s.get("State", "Enabled"))}</td></tr>'
        for s in subs
    )
    return f'<table class="data-table"><thead><tr><th>Subscription ID</th><th>Name</th><th>State</th></tr></thead><tbody>{rows}</tbody></table>'


def _resource_groups_table(rgs: list[dict]) -> str:
    if not rgs:
        return '<p class="empty">No resource groups discovered.</p>'
    rows = "".join(
        f'<tr><td>{esc(r.get("ResourceGroup", ""))}</td>'
        f'<td>{esc(r.get("SubscriptionName", ""))}</td>'
        f'<td>{esc(r.get("Location", ""))}</td></tr>'
        for r in sorted(rgs, key=lambda x: x.get("ResourceGroup", ""))
    )
    return f'<table class="data-table"><thead><tr><th>Resource Group</th><th>Subscription</th><th>Location</th></tr></thead><tbody>{rows}</tbody></table>'


def _resource_type_table(counts: dict[str, int]) -> str:
    if not counts:
        return '<p class="empty">No resources discovered.</p>'
    rows = "".join(
        f'<tr><td><code>{esc(rt)}</code></td><td>{c}</td></tr>'
        for rt, c in sorted(counts.items(), key=lambda x: -x[1])
    )
    return f'<table class="data-table"><thead><tr><th>Resource Type</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>'


def _rbac_table(assignments: list[dict]) -> str:
    if not assignments:
        return '<p class="empty">No privileged assignments found.</p>'
    rows = []
    for ra in assignments:
        role = esc(ra.get("RoleName") or ra.get("RoleDefinitionName", ""))
        principal = esc(ra.get("PrincipalName") or ra.get("PrincipalDisplayName", ""))
        ptype = esc(ra.get("PrincipalType", ""))
        scope = esc(ra.get("ScopeLevel") or _scope_level(ra.get("Scope", "")))
        sub = esc(ra.get("SubscriptionName", ""))
        rows.append(f'<tr><td>{role}</td><td>{principal}</td><td>{ptype}</td><td>{scope}</td><td>{sub}</td></tr>')
    return (
        '<table class="data-table"><thead><tr><th>Role</th><th>Principal</th><th>Type</th><th>Scope</th><th>Subscription</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _scope_level(scope: str) -> str:
    if "/managementGroups/" in scope:
        return "ManagementGroup"
    if "/resourceGroups/" in scope and "/providers/" in scope:
        return "Resource"
    if "/resourceGroups/" in scope:
        return "ResourceGroup"
    if "/subscriptions/" in scope:
        return "Subscription"
    return "Unknown"


def _policy_table(policies: list[dict]) -> str:
    if not policies:
        return '<p class="empty">No policy assignments discovered.</p>'
    rows = []
    for p in policies:
        name = esc(p.get("DisplayName") or p.get("Name", ""))
        scope = esc(p.get("Scope", "")[-80:])
        enforcement = esc(p.get("EnforcementMode", "Default"))
        rows.append(f'<tr><td>{name}</td><td><code>{scope}</code></td><td>{enforcement}</td></tr>')
    return (
        '<table class="data-table"><thead><tr><th>Policy</th><th>Scope</th><th>Enforcement</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _tenant_info_table(tenant: dict) -> str:
    if not tenant:
        return '<p class="empty">Tenant information not available.</p>'
    rows = "".join(
        f'<tr><td>{esc(k)}</td><td>{esc(str(v))}</td></tr>'
        for k, v in tenant.items() if v
    )
    return f'<table class="data-table"><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>'


def _entra_roles_table(roles: list[dict], role_members: list[dict], access_denied: list[dict] | None = None) -> str:
    """Show directory roles with member details.  Handles full data, partial data (timeout), and no data."""
    ad_names = {ad.get("collector", "") for ad in (access_denied or [])}

    if not roles and not role_members:
        if "EntraRoles" in ad_names:
            return (
                '<div class="access-info">'
                '<strong>&#128274; Access Denied:</strong> The <code>EntraRoles</code> collector was blocked '
                'by insufficient permissions (HTTP 403). When running with <code>az login</code>, the Azure CLI '
                'app may not have consent for the required Graph scopes. Either assign your user account the '
                '<strong>Global Reader</strong> or <strong>Directory Reader</strong> Entra role, or use the '
                '<code>appregistration</code> auth mode with a dedicated app that has '
                '<code>RoleManagement.Read.Directory</code> consented. '
                'See <a href="#evidence-gaps" style="color:var(--primary)">Evidence Gaps</a> for details.'
                '</div>'
            )
        return '<p class="empty">No directory roles discovered.</p>'

    # Build role-name → list of member display names from directory-role-member records
    members_by_role: dict[str, list[str]] = {}
    for m in role_members:
        rname = m.get("RoleName", "")
        member_name = m.get("MemberDisplayName") or m.get("MemberUPN", "")
        if rname and member_name:
            members_by_role.setdefault(rname, []).append(member_name)

    # If we have member data (from directory_roles.members API), show the enriched table
    has_member_data = bool(members_by_role)

    # When roles list is empty but role_members has data (partial timeout recovery),
    # synthesize role definitions from the member records
    if not roles and role_members:
        seen: set[str] = set()
        for m in role_members:
            rname = m.get("RoleName", "")
            if rname and rname not in seen:
                seen.add(rname)
                roles.append({
                    "DisplayName": rname,
                    "RoleId": m.get("RoleId", ""),
                    "IsBuiltIn": True,
                    "IsPrivileged": m.get("IsPrivilegedRole", rname in [
                        "Global Administrator", "Privileged Role Administrator",
                        "Application Administrator", "Cloud Application Administrator",
                        "Exchange Administrator", "SharePoint Administrator",
                        "User Administrator", "Authentication Administrator",
                        "Security Administrator", "Conditional Access Administrator",
                    ]),
                })

    # Build displayable rows
    active_roles = []
    for r in roles:
        display_name = r.get("DisplayName") or r.get("displayName", "")
        members = members_by_role.get(display_name, [])
        if has_member_data:
            # Only include roles with assigned members when member data is available
            if members:
                active_roles.append((r, members))
        else:
            # No member data — include all roles to show accurate definitions
            active_roles.append((r, members))

    if not active_roles:
        return (
            f'<p class="empty">No roles with assigned members found '
            f'({len(roles)} role definitions exist, but no membership data was collected).</p>'
        )

    active_roles.sort(key=lambda x: (
        0 if x[0].get("IsPrivileged") else 1,
        -len(x[1]),
        x[0].get("DisplayName", ""),
    ))

    # Choose table layout based on available data
    if has_member_data:
        # Full table with member details
        rows = []
        for r, members in active_roles:
            display_name = esc(r.get("DisplayName") or r.get("displayName", ""))
            is_priv = r.get("IsPrivileged", False)
            priv_badge = '<span class="badge" style="background:#D13438">Privileged</span>' if is_priv else ""
            member_count = len(members)
            member_list = ", ".join(esc(m) for m in sorted(set(members))[:15])
            if len(set(members)) > 15:
                member_list += f" … +{len(set(members)) - 15} more"
            rows.append(
                f'<tr><td><strong>{display_name}</strong></td>'
                f'<td>{priv_badge}</td>'
                f'<td>{member_count}</td>'
                f'<td style="font-size:12px">{member_list}</td></tr>'
            )
        heading = (
            f'<p style="margin-bottom:8px;color:var(--text-secondary);font-size:13px">'
            f'{len(active_roles)} active roles (of {len(roles)} total definitions) have assigned members.</p>'
        )
        table = (
            '<table class="data-table"><thead><tr>'
            '<th>Role</th><th>Classification</th><th>Members</th><th>Assigned Users / Groups</th>'
            '</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )
    else:
        # Definitions-only table (no member data — e.g. timeout during Stage 4)
        rows = []
        for r, _ in active_roles:
            display_name = esc(r.get("DisplayName") or r.get("displayName", ""))
            is_priv = r.get("IsPrivileged", False)
            priv_badge = '<span class="badge" style="background:#D13438">Privileged</span>' if is_priv else ""
            is_builtin = "Yes" if r.get("IsBuiltIn", True) else "No"
            is_enabled = "Yes" if r.get("IsEnabled", True) else "No"
            rows.append(
                f'<tr><td><strong>{display_name}</strong></td>'
                f'<td>{priv_badge}</td>'
                f'<td>{is_builtin}</td>'
                f'<td>{is_enabled}</td></tr>'
            )
        heading = (
            f'<div class="access-info" style="border-left-color:var(--ms-yellow)">'
            f'<strong>&#9888; Partial Data:</strong> {len(roles)} role definitions were collected, '
            f'but member assignment data could not be retrieved (collector timed out or failed). '
            f'Role definitions are shown below. Re-run the assessment to collect full membership data.'
            f'</div>'
        )
        table = (
            '<table class="data-table"><thead><tr>'
            '<th>Role</th><th>Classification</th><th>Built-In</th><th>Enabled</th>'
            '</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )

    return heading + table


def _applications_table(apps: list[dict], sps: list[dict]) -> str:
    """Detailed table of application registrations with security-relevant columns,
    and service principals sub-categorized by type."""
    if not apps:
        return '<p class="empty">No application registrations discovered.</p>'
    rows = []
    for a in apps:
        data = a.get("Data") or a
        name = esc(data.get("DisplayName", ""))
        mt = "Yes" if data.get("IsMultiTenant") else "No"
        audience = esc(data.get("SignInAudience", ""))
        creds = data.get("TotalCredentials", 0)
        pwd_count = data.get("PasswordCredentialCount", 0)
        key_count = data.get("KeyCredentialCount", 0)
        expired = data.get("HasExpiredCredentials", False)
        expiring = data.get("HasExpiringCredentials", False)
        cred_status = ""
        if expired:
            cred_status = '<span style="color:var(--ms-red);font-weight:600">Expired</span>'
        elif expiring:
            cred_status = '<span style="color:var(--ms-orange)">Expiring Soon</span>'
        elif creds > 0:
            cred_status = '<span style="color:var(--ms-green)">Valid</span>'
        else:
            cred_status = '<span style="color:var(--text-muted)">None</span>'
        rows.append(
            f'<tr><td>{name}</td><td>{mt}</td><td><code style="font-size:11px">{audience}</code></td>'
            f'<td>{pwd_count}</td><td>{key_count}</td><td>{cred_status}</td></tr>'
        )
    apps_html = (
        '<details class="sub-section">'
        f'<summary>Application Registrations ({len(apps):,})</summary>'
        '<div class="sub-content">'
        '<table class="data-table"><thead><tr><th>Application</th><th>Multi-Tenant</th>'
        '<th>Sign-In Audience</th><th>Passwords</th><th>Certificates</th><th>Credential Status</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
        '</div></details>'
    )

    # Service Principals sub-categorized by type
    sp_html = ""
    if sps:
        sp_by_type: dict[str, list[dict]] = {}
        for sp in sps:
            data = sp.get("Data") or sp
            sp_type = data.get("ServicePrincipalType", data.get("servicePrincipalType", "Other")) or "Other"
            sp_by_type.setdefault(sp_type, []).append(data)

        sp_parts: list[str] = []
        # Sort types: Application first, then ManagedIdentity, then rest alphabetically
        type_order = {"Application": 0, "ManagedIdentity": 1}
        sorted_types = sorted(sp_by_type.keys(), key=lambda t: (type_order.get(t, 99), t))

        for sp_type in sorted_types:
            type_sps = sp_by_type[sp_type]
            sp_rows = []
            for data in type_sps:
                sp_name = esc(data.get("DisplayName", ""))
                sp_enabled = "Yes" if data.get("AccountEnabled", data.get("accountEnabled", True)) else "No"
                sp_app_id = esc(data.get("AppId", data.get("appId", "")))
                sp_creds = data.get("TotalCredentials", 0)
                sp_expired = data.get("HasExpiredCredentials", False)
                cred_info = ""
                if sp_creds > 0:
                    cred_info = f'<span style="color:var(--ms-red);font-weight:600">Expired ({sp_creds})</span>' if sp_expired else f'{sp_creds}'
                sp_rows.append(
                    f'<tr><td>{sp_name}</td><td><code style="font-size:11px">{sp_app_id}</code></td>'
                    f'<td>{sp_enabled}</td><td>{cred_info}</td></tr>'
                )
            type_label = esc(sp_type)
            sp_parts.append(
                f'<details class="sub-section">'
                f'<summary>{type_label} ({len(type_sps):,})</summary>'
                f'<div class="sub-content">'
                f'<table class="data-table"><thead><tr><th>Name</th><th>App ID</th>'
                f'<th>Enabled</th><th>Credentials</th></tr></thead>'
                f'<tbody>{"".join(sp_rows)}</tbody></table>'
                f'</div></details>'
            )
        sp_html = (
            f'<details class="sub-section">'
            f'<summary>Service Principals ({len(sps):,} total)</summary>'
            f'<div class="sub-content">{"".join(sp_parts)}</div>'
            f'</details>'
        )
    else:
        sp_html = '<p style="color:var(--text-secondary);margin-top:8px">No service principals discovered.</p>'

    return apps_html + sp_html


def _ca_policies_table(policies: list[dict]) -> str:
    if not policies:
        return '<p class="empty">No Conditional Access policies discovered.</p>'
    rows = []
    for p in policies:
        name = esc(p.get("DisplayName") or p.get("displayName", ""))
        state = esc(p.get("State") or p.get("state", ""))
        mfa = "Yes" if _requires_mfa(p) else "No"
        rows.append(f'<tr><td>{name}</td><td>{state}</td><td>{mfa}</td></tr>')
    return f'<table class="data-table"><thead><tr><th>Policy</th><th>State</th><th>Requires MFA</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'


def _requires_mfa(policy: dict) -> bool:
    gc = policy.get("GrantControls") or policy.get("grantControls") or {}
    if isinstance(gc, list):
        # GrantControls is already a flat list of control names
        return "mfa" in [str(b).lower() for b in gc]
    if not isinstance(gc, dict):
        return False
    builtins = gc.get("BuiltInControls") or gc.get("builtInControls") or []
    return "mfa" in [str(b).lower() for b in builtins]


def _users_summary(users: dict, mfa: dict) -> str:
    if not users and not mfa:
        return ""
    inner_parts: list[str] = []
    if users:
        total = users.get("TotalUsers") or users.get("totalUsers", 0)
        guests = users.get("GuestUsers") or users.get("guestUsers", 0)
        members = users.get("MemberUsers") or users.get("memberUsers", 0)
        enabled = users.get("EnabledUsers") or users.get("enabledUsers", 0)
        disabled = users.get("DisabledUsers") or users.get("disabledUsers", 0)
        inner_parts.append(f"""
        <table class="data-table">
        <thead><tr><th>Metric</th><th>Count</th></tr></thead>
        <tbody>
          <tr><td>Total Users</td><td>{total:,}</td></tr>
          <tr><td>Member Users</td><td>{members:,}</td></tr>
          <tr><td>Guest Users</td><td>{guests:,}</td></tr>
          <tr><td>Enabled</td><td>{enabled:,}</td></tr>
          <tr><td>Disabled</td><td>{disabled:,}</td></tr>
        </tbody></table>""")
    if mfa:
        registered = mfa.get("MfaRegistered") or mfa.get("mfaRegistered", 0)
        total_mfa = mfa.get("TotalUsers") or mfa.get("totalUsers", 0)
        pct = (registered / total_mfa * 100) if total_mfa > 0 else 0
        inner_parts.append(f'<p style="margin-top:8px">MFA Registered: <strong>{registered:,}</strong> of {total_mfa:,} ({pct:.1f}%)</p>')
    content = "\n".join(inner_parts)
    return (
        f'<details class="sub-section">'
        f'<summary>4.5 User Demographics</summary>'
        f'<div class="sub-content">{content}</div>'
        f'</details>'
    )


# ── Compliance sections ──────────────────────────────────────────────────

# Framework descriptions for tooltips
_FW_TIPS: dict[str, str] = {
    "FedRAMP": "Federal Risk and Authorization Management Program.\\n• US government standard for cloud authorization\\n• Covers 69 security controls across 10 domains\\n• Score = compliant / total controls",
    "CIS": "CIS Azure Foundations Benchmark v2.0.\\n• Industry-standard security baseline for Microsoft Azure\\n• Practical, consensus-driven configuration guidance\\n• Score = compliant / total controls",
    "ISO-27001": "ISO/IEC 27001:2022 Information Security Management.\\n• International standard for ISMS\\n• Risk-based approach to information security\\n• Score = compliant / total controls",
    "NIST-800-53": "NIST SP 800-53 Rev 5 Security Controls.\\n• Comprehensive catalog for federal systems\\n• 83 controls spanning 10+ security families\\n• Score = compliant / total controls",
    "PCI-DSS": "PCI Data Security Standard v4.0.\\n• Requirements for cardholder data protection\\n• Mandatory for organizations handling payment cards\\n• Score = compliant / total controls",
    "MCSB": "Microsoft Cloud Security Benchmark.\\n• Microsoft-recommended security posture for Azure\\n• Maps to CIS, NIST, and PCI-DSS controls\\n• Score = compliant / total controls",
    "HIPAA": "HIPAA Security Rule.\\n• US regulation for electronic health information (ePHI)\\n• Administrative, physical, and technical safeguards\\n• Score = compliant / total controls",
    "SOC2": "SOC 2 Type II Trust Services Criteria.\\n• Security, availability, processing integrity, confidentiality, privacy\\n• Required for SaaS and service organizations\\n• Score = compliant / total controls",
    "GDPR": "General Data Protection Regulation (EU).\\n• Data protection and privacy for EU individuals\\n• Covers data processing, storage, and transfer\\n• Score = compliant / total controls",
    "NIST-CSF": "NIST Cybersecurity Framework.\\n• Voluntary framework for cybersecurity risk management\\n• Identify, Protect, Detect, Respond, Recover\\n• Score = compliant / total controls",
    "CSA-CCM": "Cloud Security Alliance Cloud Controls Matrix.\\n• Security control framework for cloud computing\\n• 24 controls across multiple domains\\n• Score = compliant / total controls",
}

# Domain descriptions for tooltips
_DOMAIN_TIPS: dict[str, str] = {
    "access": "Access Control.\\n• Evaluates RBAC role assignments, least-privilege enforcement\\n• Checks Owner/Contributor counts, scope levels\\n• Covers privileged access management and separation of duties",
    "identity": "Identity & Authentication.\\n• Evaluates MFA enforcement, Conditional Access policies\\n• Checks user sign-in risk policies, password policies\\n• Covers identity governance and lifecycle management",
    "data_protection": "Data Protection.\\n• Evaluates encryption at rest and in transit\\n• Checks storage account security, Key Vault configuration\\n• Covers data classification, retention, and DLP policies",
    "logging": "Logging & Monitoring.\\n• Evaluates diagnostic settings, activity log retention\\n• Checks Azure Monitor, Log Analytics workspace configuration\\n• Covers alert rules, audit trails, and SIEM integration",
    "network": "Network Security.\\n• Evaluates NSG rules, virtual network configuration\\n• Checks public endpoint exposure, TLS/SSL settings\\n• Covers network segmentation, firewall rules, and DDoS protection",
    "governance": "Governance & Risk.\\n• Evaluates Azure Policy assignments, compliance state\\n• Checks resource tagging, naming conventions\\n• Covers regulatory compliance, risk assessment, and security posture",
}

def _framework_cards(fw_summaries: dict) -> str:
    if not fw_summaries:
        return '<p class="empty">Single framework assessment.</p>'
    cards = []
    for fw_key, fws in fw_summaries.items():
        s = fws.get("ComplianceScore", 0)
        c = score_color(s)
        tip = _FW_TIPS.get(fw_key, f"{fw_key} compliance framework.\\n• Score = compliant / total controls")
        nc = fws.get("NonCompliant", 0)
        comp = fws.get("Compliant", 0)
        total = fws.get("TotalControls", 0)
        tip_full = f"{tip}\\n• Current: {comp}/{total} compliant, {nc} non-compliant"
        cards.append(f"""
        <div class="domain-card" data-tip="{esc(tip_full)}" tabindex="0">
          <div class="domain-icon">&#128203;</div>
          <div class="domain-name">{esc(fws.get('FrameworkName', fw_key))}</div>
          <div class="domain-score" style="color:{c}">{s:.0f}%</div>
          <div class="domain-detail">{comp}/{total} compliant</div>
          <div class="domain-detail" style="color:var(--ms-red)">{nc} non-compliant</div>
        </div>""")
    return f'<div class="domain-grid">{"".join(cards)}</div>'


def _domain_cards(scores: dict) -> str:
    cards = []
    for domain, data in scores.items():
        meta = DOMAIN_META.get(domain, {"name": domain.title(), "icon": "&#128193;"})
        s = data.get("Score", 0)
        c = score_color(s)
        comp = data.get("Compliant", 0)
        total = data.get("Total", 0)
        me = data.get("MissingEvidence", 0)
        nc = total - comp
        default_tip = f"{meta['name']}.\\n• {comp}/{total} compliant controls\\n• Score = compliant / total"
        tip = _DOMAIN_TIPS.get(domain, default_tip)
        me_tip = f"\\n• {me} controls skipped (resource not in environment)" if me else ""
        tip_full = f"{tip}\\n• Current: {comp}/{total} compliant, {nc} gaps{me_tip}"
        me_line = f'\n          <div class="domain-detail" style="color:#888;font-size:0.75rem">{me} N/A</div>' if me else ""
        cards.append(f"""
        <div class="domain-card" data-tip="{esc(tip_full)}" tabindex="0">
          <div class="domain-icon">{meta['icon']}</div>
          <div class="domain-name">{esc(meta['name'])}</div>
          <div class="domain-score" style="color:{c}">{s:.0f}%</div>
          <div class="domain-detail">{comp}/{total} compliant</div>{me_line}
        </div>""")
    return "\n".join(cards) if cards else '<p class="empty">No domain data available.</p>'


def _control_rows(controls: list, findings: list | None = None) -> str:
    # Build findings lookup for description preview and resource count
    finding_info: dict[str, dict] = {}
    if findings:
        for f in findings:
            cid_f = f.get("ControlId", "")
            if cid_f not in finding_info:
                finding_info[cid_f] = {"descs": [], "seen": set(), "resources": 0}
            desc = f.get("Description", "")
            desc_key = desc.strip().lower()
            if desc_key and desc_key not in finding_info[cid_f]["seen"]:
                finding_info[cid_f]["seen"].add(desc_key)
                finding_info[cid_f]["descs"].append(desc)
            se = f.get("SupportingEvidence", [])
            if se and isinstance(se, list):
                finding_info[cid_f]["resources"] += sum(1 for ev in se if ev.get("ResourceName"))
    rows = []
    for c in sorted(controls, key=lambda x: (sev_order(x.get("Severity", "medium")), x.get("ControlId", ""))):
        cid = esc(c.get("ControlId", ""))
        cid_raw = c.get("ControlId", "")
        title = esc(c.get("ControlTitle", ""))
        domain = c.get("Domain", "")
        sev = c.get("Severity", "medium")
        status_key = c.get("Status", "not_assessed")
        fc = c.get("FindingCount", 0)
        fw = esc(humanize_framework(c.get("Framework", "")))
        info = finding_info.get(cid_raw, {})
        preview = esc(info["descs"][0][:120]) if info.get("descs") else ""
        ellipsis = "..." if info.get("descs") and len(info["descs"][0]) > 120 else ""
        res_count = info.get("resources", 0)
        rows.append(
            f'<tr id="ctrl-{cid}" data-severity="{sev}" data-domain="{esc(domain)}" '
            f'data-status="{status_key}">'
            f'<td><code>{cid}</code></td><td>{title}</td>'
            f'<td>{fw}</td>'
            f'<td>{esc(humanize_domain(domain))}</td>'
            f'<td>{severity_badge(sev)}</td>'
            f'<td>{status_badge(status_key)}</td>'
            f'<td style="font-size:12px;color:var(--text-secondary)">{preview}{ellipsis}</td>'
            f'<td>{fc}</td>'
            f'<td>{res_count}</td></tr>'
        )
    return "\n".join(rows)


def _detailed_findings(findings: list) -> str:
    """Render findings as a searchable table with click-to-popup detail panels."""
    if not findings:
        return '<p class="empty">No findings to display.</p>'

    # Group findings by ControlId, de-duplicate by description
    groups: dict[str, dict] = {}
    for f in sorted(findings, key=lambda x: sev_order(x.get("Severity", "medium"))):
        cid = f.get("ControlId", "unknown")
        if cid not in groups:
            groups[cid] = {
                "control_id": cid,
                "control_title": f.get("ControlTitle", ""),
                "severity": f.get("Severity", "medium"),
                "status": f.get("Status", "not_assessed"),
                "framework": f.get("Framework", ""),
                "domain": f.get("Domain", ""),
                "sub_findings": [],
                "seen_descs": set(),
            }
        desc = f.get("Description", "")
        rec = f.get("Recommendation", "")
        resources: list[dict] = []
        se = f.get("SupportingEvidence", [])
        if se and isinstance(se, list):
            for ev in se:
                rname = ev.get("ResourceName", "")
                rtype = ev.get("ResourceType", "")
                if rname:
                    resources.append({"name": rname, "type": rtype})

        desc_key = desc.strip().lower()
        if desc_key not in groups[cid]["seen_descs"]:
            groups[cid]["seen_descs"].add(desc_key)
            groups[cid]["sub_findings"].append({
                "description": desc,
                "recommendation": rec,
                "status": f.get("Status", "not_assessed"),
                "resources": resources,
            })
        else:
            for sf in groups[cid]["sub_findings"]:
                if sf["description"].strip().lower() == desc_key:
                    sf["resources"].extend(resources)
                    break

    # Build table rows
    table_rows: list[str] = []

    for idx, (cid, grp) in enumerate(groups.items()):
        sev = grp["severity"]
        status_key = grp["status"]
        fw_display = esc(humanize_framework(grp["framework"]))
        domain_display = esc(humanize_domain(grp["domain"]))
        finding_count = len(grp["sub_findings"])
        # Count total affected resources
        total_resources = sum(len(sf["resources"]) for sf in grp["sub_findings"])
        # First description as preview
        preview = esc(grp["sub_findings"][0]["description"][:120]) if grp["sub_findings"] else ""
        ellipsis = "..." if grp["sub_findings"] and len(grp["sub_findings"][0]["description"]) > 120 else ""

        table_rows.append(
            f'<tr data-severity="{sev}" data-domain="{esc(grp["domain"])}" '
            f'data-status="{status_key}">'
            f'<td><a href="#ctrl-{esc(cid)}" style="text-decoration:none"><code>{esc(cid)}</code></a></td>'
            f'<td>{esc(grp["control_title"])}</td>'
            f'<td>{severity_badge(sev)}</td>'
            f'<td>{status_badge(status_key)}</td>'
            f'<td>{fw_display}</td>'
            f'<td>{domain_display}</td>'
            f'<td style="font-size:12px;color:var(--text-secondary)">{preview}{ellipsis}</td>'
            f'<td>{finding_count}</td>'
            f'<td>{total_resources}</td>'
            f'</tr>'
        )

    table_html = (
        '<table class="data-table" id="findings-table">'
        '<thead><tr><th>Control</th><th>Title</th><th>Severity</th><th>Status</th>'
        '<th>Framework</th><th>Domain</th><th>Description</th><th>Findings</th><th>Resources</th></tr></thead>'
        f'<tbody>{"".join(table_rows)}</tbody></table>'
    )

    return table_html


def _remediation_roadmap(findings: list) -> str:
    nc = [f for f in findings if f.get("Status") == "non_compliant"]
    if not nc:
        return '<p class="empty">No remediation actions needed.</p>'
    nc.sort(key=lambda f: sev_order(f.get("Severity", "medium")))
    groups: dict[str, list] = {}
    for f in nc:
        groups.setdefault(f.get("Severity", "medium"), []).append(f)

    parts = []
    priority = 1
    for sev in ["critical", "high", "medium", "low"]:
        items = groups.get(sev, [])
        if not items:
            continue
        color = SEVERITY_COLORS.get(sev, "#A8A6A3")
        parts.append(f'<h3 style="color:{color}">Priority {priority}: {sev.upper()} ({len(items)} items) &mdash; {"0-14" if sev in ("critical",) else "0-30" if sev == "high" else "30-90" if sev == "medium" else "90-180"} days</h3>')
        parts.append('<div class="roadmap-items">')
        seen = set()
        for f in items:
            rec = f.get("Recommendation", "")
            desc = f.get("Description", "")
            key = f.get("ControlId", "") + (rec or desc)
            if key in seen:
                continue
            seen.add(key)
            cid = esc(f.get("ControlId", ""))
            parts.append(f"""
            <div class="finding-card {sev}">
              <div class="finding-header">
                <code>{cid}</code> {severity_badge(sev)}
                <span style="color:var(--text-muted);font-size:11px">{esc(humanize_framework(f.get('Framework', '')))}</span>
              </div>
              <p class="finding-desc">{esc(desc)}</p>
              {"<div class='remediation'><strong>Action:</strong> " + esc(rec) + "</div>" if rec else ""}
            </div>""")
        parts.append('</div>')
        priority += 1
    return "\n".join(parts)


def _top_risks_table(findings: list) -> str:
    """Top 10 critical non-compliant findings, de-duplicated by control."""
    nc = [f for f in findings if f.get("Status") == "non_compliant"]
    if not nc:
        return '<p class="empty">No non-compliant findings.</p>'
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
    rows = "".join(
        f'<tr><td>{i}</td><td><a href="#ctrl-{esc(r.get("ControlId", ""))}" style="text-decoration:none"><code>{esc(r.get("ControlId", ""))}</code></a></td>'
        f'<td>{esc(r.get("ControlTitle", ""))}</td>'
        f'<td>{severity_badge(r.get("Severity", "medium"))}</td>'
        f'<td style="font-size:12px">{esc(r.get("Description", "")[:200])}</td>'
        f'<td style="font-size:12px">{esc(r.get("Recommendation", "")[:200])}</td>'
        f'<td><span class="badge" style="background:{SEVERITY_COLORS.get(r.get("Severity","medium"),"#A8A6A3")}">{"P0" if r.get("Severity")=="critical" else "P1" if r.get("Severity")=="high" else "P2"}</span></td></tr>'
        for i, r in enumerate(top, 1)
    )
    return (f'<table class="data-table"><thead><tr>'
            f'<th>#</th><th>Control</th><th>Title</th><th>Severity</th><th>Description</th><th>Recommendation</th><th>Priority</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>')


def _effort_matrix_table(findings: list) -> str:
    """Enriched remediation effort matrix with resource counts, examples, and effort level."""
    nc = [f for f in findings if f.get("Status") in ("non_compliant", "partial")]
    if not nc:
        return '<p class="empty">No gaps to remediate.</p>'
    timeline = {
        "critical": ("Immediate (0-14d)", "#D13438", "High"),
        "high": ("Urgent (0-30d)", "#F7630C", "High"),
        "medium": ("Short-term (30-90d)", "#FFB900", "Medium"),
        "low": ("Long-term (90-180d)", "#107C10", "Low"),
    }
    rows = []
    for sev, (label, color, effort) in timeline.items():
        group = [f for f in nc if f.get("Severity", "").lower() == sev]
        if group:
            # Count unique controls and affected resources
            unique_controls = len(set(f.get("ControlId", "") for f in group))
            resource_count = sum(
                len(f.get("SupportingEvidence", []))
                for f in group
                if f.get("SupportingEvidence")
            )
            # Top example
            example = group[0].get("ControlTitle", "")[:60]
            rows.append(
                f'<tr><td style="color:{color};font-weight:600">{sev.upper()}</td>'
                f'<td>{len(group)}</td>'
                f'<td>{unique_controls}</td>'
                f'<td>{resource_count}</td>'
                f'<td><span class="badge" style="background:{color}">{effort}</span></td>'
                f'<td>{label}</td>'
                f'<td style="font-size:12px;color:var(--text-secondary)">{esc(example)}{"..." if len(group[0].get("ControlTitle", "")) > 60 else ""}</td></tr>'
            )
    return (f'<table class="data-table"><thead><tr>'
            f'<th>Severity</th><th>Findings</th><th>Controls</th><th>Resources</th><th>Effort</th><th>Timeline</th><th>Example</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table>')


def _next_steps_dynamic(findings: list, access_denied: list | None) -> str:
    """Generate data-driven next-steps from actual findings (B10)."""
    nc = [f for f in findings if f.get("Status") == "non_compliant"]
    crit = [f for f in nc if f.get("Severity") == "critical"]
    high = [f for f in nc if f.get("Severity") == "high"]
    med = [f for f in nc if f.get("Severity") == "medium"]
    ad_count = len(access_denied) if access_denied else 0

    parts: list[str] = []

    # --- Immediate actions (from real critical/high findings) ---
    urgent = crit + high
    if urgent:
        parts.append('<h3 style="color:#D13438">&#9888; Immediate Actions (0-14 days)</h3><ol>')
        seen: set[str] = set()
        for f in urgent[:5]:
            rec = f.get("Recommendation", "") or f.get("Description", "")
            cid = f.get("ControlId", "")
            key = cid + rec[:80]
            if key in seen:
                continue
            seen.add(key)
            sev = f.get("Severity", "high")
            parts.append(
                f'<li>{severity_badge(sev)} <strong>{esc(cid)}</strong> &mdash; '
                f'{esc(rec[:200])}{"..." if len(rec) > 200 else ""}</li>'
            )
        parts.append('</ol>')

    # --- Short-term actions ---
    if med:
        unique_med = len(set(f.get("ControlId", "") for f in med))
        parts.append(
            f'<h3 style="color:#FFB900">&#128339; Short-Term Actions (14-90 days)</h3>'
            f'<p>Address the remaining <strong>{unique_med}</strong> medium-severity controls. '
            f'Focus on domains with the highest gap counts first — see the '
            f'<a href="#remediation">Remediation Roadmap</a> for prioritised guidance.</p>'
        )

    # --- Access-denied resolution ---
    if ad_count:
        parts.append(
            f'<h3 style="color:#F7630C">&#128274; Resolve Access Gaps</h3>'
            f'<p><strong>{ad_count}</strong> resource{"s" if ad_count != 1 else ""} returned '
            f'<em>Access Denied</em>. When running with <code>az login</code>, the Azure CLI app may lack '
            f'consent for certain Graph scopes. Assign your user account the <strong>Global Reader</strong> '
            f'or <strong>Security Reader</strong> Entra role, or use the <code>appregistration</code> auth '
            f'mode with a dedicated app registration that has the required permissions consented.</p>'
        )

    # --- Continuous improvement ---
    total_nc = len(nc)
    parts.append(
        '<h3 style="color:#0078D4">&#128260; Continuous Improvement</h3><ol>'
        '<li><strong>Re-assess after remediation</strong> &mdash; run PostureIQ again to '
        'verify fixes and update your compliance score.</li>'
        '<li><strong>Automate enforcement</strong> &mdash; convert high-value controls into '
        'Azure Policy <code>Deny</code> / <code>DeployIfNotExists</code> assignments.</li>'
        '<li><strong>Schedule regular scans</strong> &mdash; integrate PostureIQ into your '
        'CI/CD pipeline or run monthly assessments to prevent regression.</li>'
    )
    if total_nc > 20:
        parts.append(
            f'<li><strong>Consider phased remediation</strong> &mdash; with '
            f'<strong>{total_nc}</strong> non-compliant findings, prioritise critical/high '
            f'items first, then tackle medium/low in subsequent sprints.</li>'
        )
    parts.append('</ol>')

    if not nc and not ad_count:
        return ('<p style="color:#107C10;font-weight:600">&#10004; No outstanding gaps. '
                'Continue monitoring with periodic assessments.</p>')

    return "\n".join(parts)


def _missing_table(missing: list) -> str:
    if not missing:
        return '<p class="empty">All evidence types collected successfully.</p>'

    cat_colors = {
        "License / Feature Required": "#e74c3c",
        "Resource Not Deployed": "#3498db",
        "Feature Not Configured": "#f39c12",
        "Insufficient Permissions": "#e67e22",
        "API / Collector Issue": "#9b59b6",
    }

    rows: list[str] = []
    for m in missing:
        cid = esc(m.get("ControlId", ""))
        sev = m.get("Severity", "medium")
        fw = esc(m.get("Framework", ""))
        cat = m.get("PrimaryCategory", "Unknown")
        cat_color = cat_colors.get(cat, "#95a5a6")

        types_detail = m.get("TypesDetail", [])
        if types_detail:
            type_names = ", ".join(esc(td.get("DisplayName", td.get("EvidenceType", ""))) for td in types_detail)
            explanation = esc(types_detail[0].get("Explanation", ""))
            resolutions = "<br>".join(
                td.get("Resolution", "").replace("\n", "<br>")
                for td in types_detail if td.get("Resolution")
            )
        else:
            types_list = m.get("MissingTypes", [])
            type_names = ", ".join(esc(t) for t in types_list) if types_list else ""
            explanation = ""
            resolutions = ""

        resolution_html = ""
        if resolutions:
            resolution_html = (
                '<details style="font-size:12px"><summary style="cursor:pointer;color:var(--primary, #0d6efd);'
                f'font-weight:500">Resolution Steps</summary><div style="margin-top:4px;line-height:1.6">{resolutions}</div></details>'
            )

        rows.append(
            f'<tr>'
            f'<td><code>{cid}</code></td>'
            f'<td>{severity_badge(sev)}</td>'
            f'<td>{fw}</td>'
            f'<td><span style="font-size:11px;padding:2px 8px;border-radius:10px;'
            f'background:{cat_color}20;color:{cat_color};font-weight:600">{esc(cat)}</span></td>'
            f'<td style="font-size:12px">{type_names}</td>'
            f'<td style="font-size:12px">{explanation}</td>'
            f'<td>{resolution_html}</td>'
            f'</tr>'
        )

    return (
        '<table class="data-table"><thead><tr>'
        '<th>Control</th><th>Severity</th><th>Framework</th><th>Category</th>'
        '<th>Evidence Types</th><th>Explanation</th><th>Resolution</th>'
        '</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _access_denied_section(access_denied: list[dict] | None) -> str:
    if not access_denied:
        return '<p class="empty">All collectors had sufficient permissions.</p>'
    rows = "".join(
        f'<tr><td>{esc(ad.get("collector", ""))}</td><td>{esc(ad.get("source", ""))}</td>'
        f'<td>{esc(ad.get("api", ""))}</td><td>HTTP {ad.get("status_code", 403)}</td></tr>'
        for ad in access_denied
    )
    return (
        '<p style="margin-bottom:12px;color:var(--text-secondary)">The following collectors were blocked due to insufficient permissions.</p>'
        f'<table class="data-table"><thead><tr><th>Collector</th><th>Source</th><th>API</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>'
        '<div class="conf-notice" style="margin-top:12px"><strong>Note:</strong> Ensure your account has the required role assignments for the above APIs to include this data in future assessments.</div>'
    )


def _remediation_plan(findings: list, access_denied: list[dict] | None) -> str:
    """Unified remediation section: effort matrix + top risks + prioritised roadmap + next steps."""
    nc = [f for f in findings if f.get("Status") in ("non_compliant", "partial")]
    if not nc and not access_denied:
        return ('<p style="color:#107C10;font-weight:600">&#10004; No outstanding gaps. '
                'Continue monitoring with periodic assessments.</p>')

    parts: list[str] = []

    # ─── Effort Summary ───
    timeline = {
        "critical": ("Immediate (0-14 days)", "#D13438", "P0"),
        "high": ("Urgent (0-30 days)", "#F7630C", "P1"),
        "medium": ("Short-term (30-90 days)", "#FFB900", "P2"),
        "low": ("Long-term (90-180 days)", "#107C10", "P3"),
    }
    effort_rows: list[str] = []
    for sev, (label, color, priority) in timeline.items():
        group = [f for f in nc if f.get("Severity", "").lower() == sev]
        if not group:
            continue
        unique = len(set(f.get("ControlId", "") for f in group))
        res_count = sum(len(f.get("SupportingEvidence", []) or []) for f in group)
        effort_rows.append(
            f'<tr><td style="color:{color};font-weight:600">{sev.upper()}</td>'
            f'<td>{len(group)}</td><td>{unique}</td><td>{res_count}</td>'
            f'<td><span class="badge" style="background:{color}">{priority}</span></td>'
            f'<td>{label}</td></tr>'
        )
    if effort_rows:
        parts.append(
            '<h3>Effort Summary</h3>'
            '<table class="data-table"><thead><tr><th>Severity</th><th>Findings</th>'
            '<th>Controls</th><th>Resources</th><th>Priority</th><th>Timeline</th></tr></thead>'
            f'<tbody>{"".join(effort_rows)}</tbody></table>'
        )

    # ─── Prioritised Actions ───
    crit = [f for f in nc if f.get("Severity") == "critical"]
    high = [f for f in nc if f.get("Severity") == "high"]
    med = [f for f in nc if f.get("Severity") == "medium"]
    urgent = crit + high
    if urgent:
        parts.append('<h3 style="color:#D13438">&#9888; Immediate Actions (0-30 days)</h3>')
        action_rows: list[str] = []
        seen_keys: set[str] = set()
        idx = 0
        for f in urgent[:8]:
            rec = f.get("Recommendation", "") or f.get("Description", "")
            cid = f.get("ControlId", "")
            key = cid + rec[:80]
            if key in seen_keys:
                continue
            seen_keys.add(key)
            idx += 1
            sev = f.get("Severity", "high")
            timeline = "0-14 days" if sev == "critical" else "0-30 days"
            action_rows.append(
                f'<tr><td>{idx}</td>'
                f'<td><code>{esc(cid)}</code></td>'
                f'<td>{esc(f.get("ControlTitle", ""))}</td>'
                f'<td>{severity_badge(sev)}</td>'
                f'<td style="font-size:12px">{esc(rec[:200])}{"..." if len(rec) > 200 else ""}</td>'
                f'<td>{timeline}</td></tr>'
            )
        parts.append(
            '<table class="data-table"><thead><tr><th>#</th><th>Control</th><th>Title</th>'
            '<th>Severity</th><th>Recommendation</th><th>Timeline</th></tr></thead>'
            f'<tbody>{"\n".join(action_rows)}</tbody></table>'
        )

    if med:
        unique_med = len(set(f.get("ControlId", "") for f in med))
        parts.append(
            f'<h3 style="color:#FFB900">&#128339; Short-Term Actions (30-90 days)</h3>'
            f'<p>Address the remaining <strong>{unique_med}</strong> medium-severity controls. '
            f'Focus on domains with the highest gap counts first.</p>'
        )

    # ─── Access gaps ───
    ad_count = len(access_denied) if access_denied else 0
    if ad_count:
        parts.append(
            f'<h3 style="color:#F7630C">&#128274; Resolve Access Gaps</h3>'
            f'<p><strong>{ad_count}</strong> collector{"s" if ad_count != 1 else ""} returned '
            f'<em>Access Denied</em>. When running with <code>az login</code>, the Azure CLI app may lack '
            f'consent for certain Graph scopes. Assign your user account the <strong>Global Reader</strong> '
            f'or <strong>Security Reader</strong> Entra role, or use the <code>appregistration</code> auth '
            f'mode with a dedicated app registration that has the required permissions consented.</p>'
        )

    # ─── Continuous Improvement ───
    parts.append(
        '<h3 style="color:#0078D4">&#128260; Continuous Improvement</h3><ol>'
        '<li><strong>Re-assess after remediation</strong> to verify fixes and update scores.</li>'
        '<li><strong>Automate enforcement</strong> via Azure Policy <code>Deny</code> / <code>DeployIfNotExists</code> assignments.</li>'
        '<li><strong>Schedule regular scans</strong> — integrate into CI/CD or run monthly.</li>'
    )
    total_nc = len(nc)
    if total_nc > 20:
        parts.append(
            f'<li><strong>Consider phased remediation</strong> — with {total_nc} findings, '
            f'prioritise critical/high first, then tackle medium/low in subsequent sprints.</li>'
        )
    parts.append('</ol>')

    return "\n".join(parts)


def _evidence_gaps(missing: list, access_denied: list[dict] | None) -> str:
    """Unified evidence-gaps section: missing evidence + access denied collectors."""
    parts: list[str] = []

    # ─── Access Denied ───
    if access_denied:
        parts.append(f'<h3>Access Denied ({len(access_denied)} collector{"s" if len(access_denied) != 1 else ""})</h3>')
        parts.append(_access_denied_section(access_denied))

    # ─── Missing Evidence ───
    if missing:
        parts.append(f'<h3>Missing Evidence ({len(missing)} control{"s" if len(missing) != 1 else ""})</h3>')
        parts.append(_missing_table(missing))

    if not parts:
        return '<p class="empty">All evidence collected successfully. No access issues detected.</p>'

    return "\n".join(parts)


def _resource_compliance_table(findings: list) -> str:
    """Build a searchable, sortable table of per-resource compliance details."""
    # Extract resource-level rows from findings that have resource context
    rows_data = []
    for f in findings:
        resource_id = f.get("ResourceId", "")
        resource_type = f.get("ResourceType", "")
        status_key = f.get("Status", "not_assessed")
        desc = f.get("Description", "")
        rec = f.get("Recommendation", "")
        control = f.get("ControlId", "")
        sev = f.get("Severity", "medium")
        domain = f.get("Domain", "")

        # Get resource name from SupportingEvidence, finding fields, or parse from ResourceId
        se = f.get("SupportingEvidence", [])
        resource_name = ""
        if se and isinstance(se, list) and se:
            resource_name = se[0].get("ResourceName", "")
            if not resource_id:
                resource_id = se[0].get("ResourceId", "")
            if not resource_type:
                resource_type = se[0].get("ResourceType", "")

        # Fallback: check finding-level ResourceName
        if not resource_name:
            resource_name = f.get("ResourceName", "")

        # Fallback: extract name from the last segment of ResourceId
        if not resource_name and resource_id:
            segments = resource_id.rstrip("/").split("/")
            if segments:
                resource_name = segments[-1]

        # Skip findings without resource context
        if not resource_name and not resource_id:
            continue

        rows_data.append({
            "resource_id": resource_id,
            "resource_name": resource_name,
            "resource_type": resource_type,
            "status": status_key,
            "control": control,
            "severity": sev,
            "domain": domain,
            "description": desc,
            "recommendation": rec,
        })

    if not rows_data:
        return '<p class="empty">No resource-level compliance data available. Re-run the assessment to populate resource details.</p>'

    # Summary counters
    nc_resources = set()
    c_resources = set()
    for r in rows_data:
        key = r["resource_name"] or r["resource_id"]
        if r["status"] == "non_compliant":
            nc_resources.add(key)
        elif r["status"] == "compliant":
            c_resources.add(key)
    # Resources that are only compliant (no nc findings)
    compliant_only = c_resources - nc_resources

    summary_html = (
        f'<div class="stat-grid" style="margin-bottom:16px">'
        f'<div class="stat-card"><div class="stat-value">{len(rows_data)}</div><div class="stat-label">Resource Findings</div></div>'
        f'<div class="stat-card"><div class="stat-value" style="color:#D13438">{len(nc_resources)}</div><div class="stat-label">Non-Compliant Resources</div></div>'
        f'<div class="stat-card"><div class="stat-value" style="color:#107C10">{len(compliant_only)}</div><div class="stat-label">Fully Compliant Resources</div></div>'
        f'</div>'
    )

    # Search box
    search_html = (
        '<div style="margin-bottom:12px">'
        '<input type="text" id="resource-search" placeholder="Search by resource name, type, control, or status..." '
        'onkeyup="filterResourceTable()" '
        'style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:6px;'
        'background:var(--bg-secondary);color:var(--text-primary);font-size:13px">'
        '</div>'
    )

    # Build table rows
    rows_html = []
    for r in sorted(rows_data, key=lambda x: (0 if x["status"] == "non_compliant" else 1, sev_order(x["severity"]))):
        status_class = "color:#D13438" if r["status"] == "non_compliant" else "color:#107C10" if r["status"] == "compliant" else "color:#A8A6A3"
        status_label = "Non-Compliant" if r["status"] == "non_compliant" else "Compliant" if r["status"] == "compliant" else r["status"].replace("_", " ").title()

        rows_html.append(
            f'<tr>'
            f'<td title="{esc(r["resource_id"])}" style="cursor:help"><strong>{esc(r["resource_name"] or "N/A")}</strong></td>'
            f'<td><code style="font-size:11px">{esc(r["resource_type"] or "N/A")}</code></td>'
            f'<td style="{status_class};font-weight:600">{status_label}</td>'
            f'<td><code>{esc(r["control"])}</code></td>'
            f'<td>{severity_badge(r["severity"])}</td>'
            f'<td style="font-size:12px">{esc(r["description"][:200])}</td>'
            f'<td style="font-size:12px">{esc(r["recommendation"][:200]) if r["status"] == "non_compliant" and r["recommendation"] else ""}</td>'
            f'</tr>'
        )

    table_html = (
        '<table class="data-table" id="resource-compliance-table">'
        '<thead><tr>'
        '<th>Resource Name</th><th>Resource Type</th>'
        '<th>Status</th><th>Control</th><th>Severity</th>'
        '<th>Reason</th><th>Remediation</th>'
        '</tr></thead>'
        f'<tbody>{"".join(rows_html)}</tbody>'
        '</table>'
    )

    if len(rows_data) > 200:
        table_html += f'<p class="truncated-note">Showing {min(len(rows_html), len(rows_data))} of {len(rows_data)} resource findings.</p>'

    return summary_html + search_html + table_html
