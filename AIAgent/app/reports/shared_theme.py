"""
Shared HTML Theme
Common CSS, JS, and layout helpers for all HTML reports.
"""

from __future__ import annotations
from datetime import datetime, timezone

VERSION = "1.0"

FRAMEWORK_DISPLAY_NAMES: dict[str, str] = {
    "NIST-800-53": "NIST 800-53 Rev 5",
    "CIS": "CIS Azure Benchmark v2.0",
    "HIPAA": "HIPAA Security Rule",
    "PCI-DSS": "PCI DSS v4.0",
    "FedRAMP": "FedRAMP Moderate",
    "ISO-27001": "ISO 27001:2022",
    "SOC-2": "SOC 2 Type II",
    "NIST-CSF": "NIST Cybersecurity Framework",
}


def esc(s: str) -> str:
    """HTML-escape a string."""
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def get_css() -> str:
    """Return the full CSS for the professional dark/light theme."""
    return """
:root {
  --ms-blue:#0078D4; --ms-green:#107C10; --ms-red:#D13438; --ms-yellow:#FFB900; --ms-orange:#F7630C; --ms-teal:#00B7C3;
  --primary:#4EA8DE; --success:#54B054; --danger:#E74856; --warning:#FFCB3D; --info:#4FC3F7; --gray:#8A8886;
  --bg:#1B1A1F; --bg-elevated:#252429; --bg-card:#22212A; --bg-card-hover:#2A2933; --bg-subtle:#1E1D24;
  --bg-primary:#1B1A1F; --bg-secondary:#252429;
  --text:#E4E2E0; --text-secondary:#A8A6A3; --text-muted:#918F8C; --text-dim:#706E6C;
  --border:#383640; --border-light:#2E2D35;
  --th-bg:#1E1D24; --code-bg:#1A1920; --code-border:#2E2D35;
  --finding-bg:#1E1D24; --remediation-bg:#0F2818; --remediation-border:#54B054;
  --sidebar-bg:#1A1920; --sidebar-border:#2E2D35; --sidebar-link:#A8A6A3; --sidebar-link-hover:#E4E2E0;
  --sidebar-active-bg:rgba(78,168,222,0.08); --sidebar-active-border:#4EA8DE;
  --ring-track:#383640; --bar-bg:#383640;
  --conf-bg:#2C2510; --conf-border:#6E5A1A; --conf-text:#FFCB3D;
  --font-primary:'Segoe UI Variable','Segoe UI',-apple-system,BlinkMacSystemFont,'Inter',sans-serif;
  --font-mono:'Cascadia Code','Fira Code','Consolas',monospace;
  --shadow-xs:0 1px 2px rgba(0,0,0,.24); --shadow-sm:0 2px 4px rgba(0,0,0,.2),0 0 1px rgba(0,0,0,.18);
  --shadow-md:0 4px 8px rgba(0,0,0,.24),0 0 2px rgba(0,0,0,.12); --shadow-lg:0 8px 16px rgba(0,0,0,.28),0 0 2px rgba(0,0,0,.12);
}
[data-theme="light"]{
  --primary:#0078D4;--success:#107C10;--danger:#D13438;--warning:#E67700;--info:#0078D4;--gray:#A19F9D;
  --bg:#F3F2F1;--bg-elevated:#FFF;--bg-card:#FFF;--bg-card-hover:#FAFAFA;--bg-subtle:#F9F8F7;
  --bg-primary:#FFF;--bg-secondary:#F8F9FA;
  --text:#323130;--text-secondary:#605E5C;--text-muted:#696765;--text-dim:#7D7B78;
  --border:#EDEBE9;--border-light:#F3F2F1;--th-bg:#FAF9F8;--code-bg:#F3F2F1;--code-border:#EDEBE9;
  --finding-bg:#FAF9F8;--remediation-bg:#F1FAF1;--remediation-border:#107C10;
  --sidebar-bg:#FFF;--sidebar-border:#EDEBE9;--sidebar-link:#605E5C;--sidebar-link-hover:#323130;
  --sidebar-active-bg:rgba(0,120,212,.06);--sidebar-active-border:#0078D4;
  --ring-track:#EDEBE9;--bar-bg:#EDEBE9;--conf-bg:#FFF8E5;--conf-border:#FFD335;--conf-text:#7A5B00;
  --shadow-xs:0 1px 2px rgba(0,0,0,.06);--shadow-sm:0 2px 4px rgba(0,0,0,.06),0 0 1px rgba(0,0,0,.04);
  --shadow-md:0 4px 8px rgba(0,0,0,.08),0 0 2px rgba(0,0,0,.04);--shadow-lg:0 8px 16px rgba(0,0,0,.1),0 0 2px rgba(0,0,0,.04);
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth;font-size:14px}
body{font-family:var(--font-primary);font-size:1rem;line-height:1.65;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.layout{display:flex;min-height:100vh}
.sidebar{width:260px;background:var(--sidebar-bg);border-right:1px solid var(--sidebar-border);position:fixed;top:0;bottom:0;overflow-y:auto;z-index:1000;animation:slideInLeft .5s cubic-bezier(.16,1,.3,1) both}
.sidebar h2{padding:28px 24px 18px;font-size:15px;font-weight:700;letter-spacing:.3px;color:var(--primary);border-bottom:1px solid var(--sidebar-border)}
.sidebar .nav-group{font-size:10px;text-transform:uppercase;font-weight:700;color:var(--text-muted);padding:20px 24px 6px;letter-spacing:1.4px}
.sidebar nav a{display:block;padding:9px 24px;color:var(--sidebar-link);text-decoration:none;font-size:13px;border-left:3px solid transparent;transition:all .2s}
.sidebar nav a:hover{color:var(--sidebar-link-hover);background:var(--sidebar-active-bg);border-left-color:var(--primary)}
.sidebar nav a.active{color:var(--primary);background:var(--sidebar-active-bg);border-left-color:var(--sidebar-active-border);font-weight:600}
.sidebar .version{font-size:11px;color:var(--text-muted);padding:0 24px}
.sidebar-footer{padding:16px 24px;color:var(--text-muted);font-size:11px;position:absolute;bottom:0}
.theme-btn{margin:16px 24px;padding:10px 16px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:10px;color:var(--text-secondary);font-size:12px;font-weight:600;cursor:pointer;text-align:center;transition:all .2s}
.theme-btn:hover{border-color:var(--primary);color:var(--primary)}
.content{margin-left:260px;flex:1;padding:32px 40px;max-width:1200px}
.section{margin-bottom:48px}
.page-title{font-size:28px;font-weight:700;margin-bottom:8px}
.meta-bar{display:flex;gap:24px;color:var(--text-secondary);font-size:13px;margin-bottom:24px;flex-wrap:wrap}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;transition:all .2s}
.stat-card:hover{background:var(--bg-card-hover);box-shadow:var(--shadow-md)}
.stat-value{font-size:32px;font-weight:700;font-family:var(--font-mono)}
.stat-label{font-size:12px;color:var(--text-secondary);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
h2{font-size:20px;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border)}
h3{font-size:16px;margin-bottom:12px;color:var(--text-secondary)}
h4{font-size:14px;margin:16px 0 8px;color:var(--text-secondary)}
.score-display{display:flex;align-items:center;gap:40px;flex-wrap:wrap}
.ring{filter:drop-shadow(0 0 8px rgba(0,0,0,.3))}
.score-breakdown{display:flex;flex-direction:column;gap:8px}
.score-row{display:flex;align-items:center;gap:8px;font-size:14px}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.severity-summary{margin-top:24px}
.severity-bars{display:flex;flex-direction:column;gap:8px}
.sev-row{display:flex;align-items:center;gap:12px}
.sev-label{width:60px;font-size:12px;text-transform:uppercase;color:var(--text-secondary)}
.sev-track{flex:1;height:8px;background:var(--bar-bg);border-radius:4px;overflow:hidden}
.sev-fill{height:100%;border-radius:4px;transition:width .6s cubic-bezier(.16,1,.3,1)}
.sev-count{width:30px;text-align:right;font-family:var(--font-mono);font-size:13px}
.domain-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.domain-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;transition:all .3s}
.domain-card:hover{transform:translateY(-2px);box-shadow:var(--shadow-md)}
.domain-icon{font-size:28px;margin-bottom:8px}
.domain-name{font-size:13px;color:var(--text-secondary);margin-bottom:4px}
.domain-score{font-size:28px;font-weight:700;font-family:var(--font-mono)}
.domain-detail{font-size:11px;color:var(--text-muted)}
.data-table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;margin-bottom:16px}
.data-table th{background:var(--th-bg);padding:10px 12px;text-align:left;font-weight:600;border-bottom:2px solid var(--border);color:var(--text-secondary);text-transform:uppercase;font-size:11px;letter-spacing:.5px}
.data-table td{padding:10px 12px;border-bottom:1px solid var(--border-light);line-height:1.5}
.data-table tbody tr:nth-child(even) td{background:rgba(255,255,255,.03)}
.data-table tbody tr:nth-child(odd) td{background:rgba(0,0,0,.08)}
.data-table tr:hover td{background:var(--bg-card-hover)}
.data-table code{font-family:var(--font-mono);font-size:12px;color:var(--primary)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
.finding-card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;transition:all .2s}
.finding-card:hover{background:var(--bg-card-hover)}
.finding-card.non-compliant{border-left:3px solid var(--ms-red)}
.finding-card.critical{border-left:3px solid var(--ms-red)}
.finding-card.high{border-left:3px solid var(--ms-orange)}
.finding-card.medium{border-left:3px solid var(--ms-yellow)}
.finding-header{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.finding-desc{font-size:14px;color:var(--text)}
.remediation{margin-top:8px;padding:10px;background:var(--remediation-bg);border-left:3px solid var(--remediation-border);border-radius:4px;font-size:13px;color:#A5D6A7}
.missing-card{background:var(--bg-card);border:1px solid var(--border);border-left:3px solid var(--ms-yellow);border-radius:8px;padding:12px 16px;margin-bottom:8px;font-size:13px}
.missing-card code{color:var(--primary);font-family:var(--font-mono)}
.empty{color:var(--text-muted);font-style:italic}
.conf-notice{background:var(--conf-bg);border:1px solid var(--conf-border);border-radius:8px;padding:12px 16px;color:var(--conf-text);font-size:13px;margin-bottom:24px}
.doc-control-table{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:14px}
.doc-control-table th{background:var(--th-bg);padding:12px 16px;text-align:left;font-weight:600;border:1px solid var(--border);width:200px}
.doc-control-table td{padding:12px 16px;border:1px solid var(--border)}
.doc-control-table code{font-family:var(--font-mono);color:var(--primary);font-size:13px}
.roadmap-items{display:flex;flex-direction:column;gap:8px;margin-bottom:24px}
.risk-def{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.risk-def h4{margin:0 0 8px;color:var(--text)}
.risk-def p{font-size:13px;color:var(--text-secondary)}
.truncated-note{font-size:12px;color:var(--text-muted);font-style:italic;margin-top:4px}
@keyframes slideInLeft{from{transform:translateX(-20px);opacity:0}to{transform:translateX(0);opacity:1}}
.back-to-top{position:fixed;bottom:24px;right:24px;width:44px;height:44px;border-radius:50%;background:var(--primary);color:#fff;font-size:20px;border:none;cursor:pointer;opacity:0;visibility:hidden;transition:all .3s;z-index:999;display:flex;align-items:center;justify-content:center;box-shadow:var(--shadow-md)}
.back-to-top.visible{opacity:1;visibility:visible}
.back-to-top:hover{transform:scale(1.1)}
.finding-group{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;margin-bottom:12px}
.finding-group summary{padding:14px 16px;cursor:pointer;display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-weight:600}
.finding-group summary:hover{background:var(--bg-card-hover)}
.finding-group-body{padding:0 16px 16px}
.finding-group .sub-finding{padding:10px 0;border-top:1px solid var(--border-light)}
.finding-group .sub-finding:first-child{border-top:none}
.affected-resources{margin-top:6px;font-size:12px}
.affected-resources summary{cursor:pointer;color:var(--primary);font-weight:500;font-size:12px}
.affected-resources ul{margin:6px 0 0 20px;color:var(--text-secondary);font-size:12px}
.how-to-read{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:24px}
.how-to-read h4{margin-bottom:8px}
.how-to-read p{font-size:13px;color:var(--text-secondary);margin-bottom:6px}
.toc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:8px;margin:12px 0 20px}
.toc-link{display:block;padding:8px 12px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;color:var(--text);text-decoration:none;font-size:13px;transition:all .2s}
.toc-link:hover{border-color:var(--primary);color:var(--primary);background:var(--bg-card-hover)}
.toc-link .toc-num{color:var(--primary);font-weight:600;margin-right:6px}
@media(max-width:768px){.sidebar{display:none}.content{margin-left:0;padding:16px}.stat-grid{grid-template-columns:repeat(2,1fr)}}
@media print{.sidebar,.theme-btn,.back-to-top,.skip-nav,.master-controls button[onclick],.no-print{display:none!important}.content{margin-left:0;padding:16px;max-width:100%}body{background:#fff;color:#000;font-size:12px}.page-title{font-size:22px}h2{font-size:16px;page-break-after:avoid}h3{font-size:14px;page-break-after:avoid}.section{page-break-inside:avoid;margin-bottom:24px}.finding-card,.finding-group{page-break-inside:avoid}.stat-card,.finding-card,.domain-card,.missing-card{border:1px solid #ccc;background:#fff}.badge{border:1px solid #333;print-color-adjust:exact;-webkit-print-color-adjust:exact}.conf-notice{border:1px solid #999;background:#fff9e6}a{color:#000;text-decoration:none}table{page-break-inside:auto}tr{page-break-inside:avoid}}
.skip-nav{position:absolute;top:-100%;left:16px;padding:12px 24px;background:var(--primary);color:#fff;font-size:14px;font-weight:600;border-radius:0 0 8px 8px;z-index:10000;text-decoration:none;transition:top .2s}
.skip-nav:focus{top:0}
:focus-visible{outline:2px solid var(--primary);outline-offset:2px;border-radius:2px}
.sidebar nav a:focus-visible{outline-offset:-2px}
button:focus:not(:focus-visible),a:focus:not(:focus-visible){outline:none}
.theme-btn{min-height:44px;min-width:44px}
.sidebar nav a{min-height:44px;display:flex;align-items:center}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:0.01ms!important;animation-iteration-count:1!important;transition-duration:0.01ms!important;scroll-behavior:auto!important}html{scroll-behavior:auto}.sidebar{animation:none}}
@media(forced-colors:active){.badge,.stat-card,.finding-card,.domain-card,.back-to-top,.theme-btn{border:1px solid ButtonText;forced-color-adjust:none}.sidebar{border-right:1px solid ButtonText}.sidebar nav a.active{border-left-color:Highlight;color:Highlight}.skip-nav:focus{background:Highlight;color:HighlightText}.sev-fill{forced-color-adjust:none}}
"""


def get_js() -> str:
    """Return shared JS for animations and theme toggle."""
    return """
// Auto-detect OS color scheme or restore saved preference
(function(){
  var saved=localStorage.getItem('enterprisesecurityiq-theme');
  var theme=saved||(window.matchMedia('(prefers-color-scheme:light)').matches?'light':'dark');
  document.documentElement.setAttribute('data-theme',theme);
  var btn=document.querySelector('.theme-btn');
  if(btn)btn.textContent=theme==='dark'?'Switch to Light':'Switch to Dark';
})();
// Nav active state
document.querySelectorAll('.sidebar nav a').forEach(function(link){
  link.addEventListener('click',function(){
    document.querySelectorAll('.sidebar nav a').forEach(function(l){l.classList.remove('active');l.removeAttribute('aria-current')});
    this.classList.add('active');
    this.setAttribute('aria-current','true');
  });
});
// Theme toggle
function toggleTheme(){
  var html=document.documentElement;
  var current=html.getAttribute('data-theme')||'dark';
  var next=current==='dark'?'light':'dark';
  html.setAttribute('data-theme',next);
  localStorage.setItem('enterprisesecurityiq-theme',next);
  var btn=document.querySelector('.theme-btn');
  if(btn)btn.textContent=next==='dark'?'Switch to Light':'Switch to Dark';
}
// Animate counters
document.querySelectorAll('.stat-value').forEach(function(el){
  var text=el.textContent.trim();
  var match=text.match(/^([\\d,]+)/);
  if(match){
    var target=parseInt(match[1].replace(/,/g,''));
    var dur=1200;var startTime=null;
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
// Scroll-spy: highlight active sidebar link
(function(){
  var secs=document.querySelectorAll('section[id]');
  var links=document.querySelectorAll('.sidebar nav a');
  if(!secs.length||!links.length)return;
  var obs=new IntersectionObserver(function(entries){
    entries.forEach(function(e){
      if(e.isIntersecting){
        var id=e.target.getAttribute('id');
        links.forEach(function(l){
          var isActive=l.getAttribute('href')==='#'+id;
          l.classList.toggle('active',isActive);
          if(isActive)l.setAttribute('aria-current','true');else l.removeAttribute('aria-current');
        });
      }
    });
  },{rootMargin:'-20% 0px -70% 0px'});
  secs.forEach(function(s){obs.observe(s)});
})();
// Back-to-top
(function(){
  var btn=document.querySelector('.back-to-top');
  if(!btn)return;
  window.addEventListener('scroll',function(){btn.classList.toggle('visible',window.scrollY>300)});
  btn.addEventListener('click',function(){window.scrollTo({top:0,behavior:'smooth'})});
})();
// Table accessibility: add scope attributes
(function(){
  document.querySelectorAll('.data-table thead th, .master-table thead th').forEach(function(th){if(!th.hasAttribute('scope'))th.setAttribute('scope','col')});
  document.querySelectorAll('.doc-control-table th').forEach(function(th){if(!th.hasAttribute('scope'))th.setAttribute('scope','row')});
})();
"""


SEVERITY_COLORS = {
    "critical": "#D13438",
    "high": "#F7630C",
    "medium": "#FFB900",
    "low": "#107C10",
    "informational": "#A8A6A3",
}

STATUS_LABELS = {
    "compliant": ("Compliant", "#107C10"),
    "non_compliant": ("Non-Compliant", "#D13438"),
    "partial": ("Partial", "#FFB900"),
    "missing_evidence": ("Missing Evidence", "#A8A6A3"),
    "not_assessed": ("Not Assessed", "#706E6C"),
}

DOMAIN_META = {
    "access": {"name": "Access Control", "icon": "&#128272;"},
    "identity": {"name": "Identity & Authentication", "icon": "&#129682;"},
    "data_protection": {"name": "Data Protection", "icon": "&#128737;"},
    "logging": {"name": "Logging & Monitoring", "icon": "&#128202;"},
    "network": {"name": "Network Security", "icon": "&#127760;"},
    "governance": {"name": "Governance & Risk", "icon": "&#9878;"},
}


def humanize_framework(key: str) -> str:
    """Convert framework key like 'NIST-800-53' to display name."""
    return FRAMEWORK_DISPLAY_NAMES.get(key, key.replace("-", " ").replace("_", " ").title())


def humanize_domain(key: str) -> str:
    """Convert domain key like 'data_protection' to display name."""
    meta = DOMAIN_META.get(key)
    if meta:
        return meta["name"]
    return key.replace("_", " ").title()


def score_color(score: float) -> str:
    if score >= 80:
        return "#107C10"
    if score >= 60:
        return "#FFB900"
    return "#D13438"


def severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#A8A6A3")
    return f'<span class="badge" style="background:{color}">{esc(sev.upper())}</span>'


def status_badge(status_key: str) -> str:
    label, color = STATUS_LABELS.get(status_key, ("?", "#706E6C"))
    return f'<span class="badge" style="background:{color}">{label}</span>'


def sev_order(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(severity, 5)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def format_ts(ts: datetime | None = None) -> str:
    return (ts or now_utc()).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_date(ts: datetime | None = None) -> str:
    return (ts or now_utc()).strftime("%B %d, %Y")


def format_date_short(ts: datetime | None = None) -> str:
    return (ts or now_utc()).strftime("%Y-%m-%d %H:%M UTC")
