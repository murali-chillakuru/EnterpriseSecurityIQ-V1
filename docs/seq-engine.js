/* ══════════════════════════════════════════════════════════════════
   seq-engine.js — Animated Sequence Diagram Simulation Engine V2
   Replaces Mermaid sequenceDiagrams with interactive CSS-grid sims
   V3.1-style animation · Multi-step width control · Reusable API
   Author: Murali Chillakuru
   ══════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ── Inject CSS once ─────────────────────────────────────────── */
  if (!document.getElementById('seq-engine-css')) {
    var s = document.createElement('style');
    s.id = 'seq-engine-css';
    s.textContent = [
      /* ── Variables ── */
      ':root{--seq-highlight:rgba(31,111,235,.08);--seq-lifeline:#b0b8c4;--seq-arrow-active:#1F6FEB;--seq-arrow-rest:#8b949e}',
      '[data-theme="light"]{--seq-highlight:rgba(31,111,235,.06);--seq-lifeline:#c8ccd0;--seq-arrow-active:#0078D4;--seq-arrow-rest:#8b949e}',

      /* ── Sim Section Container ── */
      '.seq-sim-section{margin:1.5rem 0 2rem;background:var(--bg-card,#1C2128);border:1px solid var(--border-primary,#30363D);border-radius:12px;padding:1.25rem 1.5rem;overflow:hidden}',
      '.seq-sim-section h3.seq-title{font-size:1.1rem;font-weight:700;margin:0 0 .2rem}',
      '.seq-sim-section .seq-subtitle{font-size:.82rem;color:var(--text-secondary,#8B949E);margin:0 0 .5rem}',

      /* ── Controls Toolbar ── */
      '.seq-controls{display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-bottom:.6rem}',
      '.seq-btn{border:1px solid var(--border-primary,#30363D);background:var(--bg-card,#1C2128);color:var(--text-primary,#E6EDF3);padding:5px 12px;border-radius:5px;font-size:.72rem;font-weight:600;cursor:pointer;font-family:inherit;transition:all .2s}',
      '.seq-btn:hover{border-color:var(--seq-arrow-active);color:var(--seq-arrow-active)}',
      '.seq-btn:disabled{opacity:.35;cursor:not-allowed}',
      '.seq-btn.primary{background:var(--seq-arrow-active);color:#fff;border-color:var(--seq-arrow-active)}',
      '.seq-btn.primary:hover{opacity:.85}',
      '.seq-step-indicator{font-size:.72rem;color:var(--text-secondary,#8B949E);margin-left:6px}',

      /* ── Layout: Diagram 68% + Explain 32% (V3.1) ── */
      '.seq-layout{display:flex;gap:12px;align-items:stretch;min-height:220px}',
      '.seq-diagram-col{flex:0 0 68%;min-width:0;overflow-y:auto;overflow-x:hidden;scrollbar-width:thin;max-height:60vh}',
      '.seq-diagram-col::-webkit-scrollbar{width:4px}',
      '.seq-diagram-col::-webkit-scrollbar-thumb{background:var(--border-primary,#30363D);border-radius:2px}',
      '.seq-explain-col{flex:1 1 calc(32% - 12px);overflow-y:auto;scrollbar-width:thin;max-height:60vh}',
      '.seq-explain-col::-webkit-scrollbar{width:4px}',
      '.seq-explain-col::-webkit-scrollbar-thumb{background:var(--border-primary,#30363D);border-radius:2px}',
      '@media(max-width:900px){.seq-layout{flex-direction:column}.seq-diagram-col,.seq-explain-col{flex:1 1 100%;max-height:none}}',

      /* ── Actors (sticky grid header) ── */
      '.seq-actors{display:grid;gap:2px;position:sticky;top:0;background:var(--bg-card,#1C2128);z-index:3;padding:4px 0;border-bottom:1px solid var(--border-primary,#30363D)}',
      '.seq-actor{text-align:center}',
      '.seq-actor-icon{font-size:1.3rem;margin-bottom:1px}',
      '.seq-actor-name{font-size:.68rem;font-weight:700;line-height:1.2}',
      '.seq-actor-sub{font-size:.58rem;color:var(--text-secondary,#8B949E)}',
      '.seq-actor-tag{display:inline-block;font-size:.5rem;font-weight:700;text-transform:uppercase;letter-spacing:.3px;padding:1px 5px;border-radius:6px;margin-top:1px}',
      '.seq-actor-tag.cloud{background:#dbeafe;color:#2563eb}',
      '.seq-actor-tag.service{background:rgba(163,113,247,.12);color:#A371F7}',
      '.seq-actor-tag.engine{background:rgba(63,185,80,.12);color:#3FB950}',
      '.seq-actor-tag.data{background:rgba(210,153,34,.12);color:#D29922}',
      '.seq-actor-tag.external{background:#fee2e2;color:#dc2626}',
      '.seq-actor-tag.onprem{background:#dcfce7;color:#16a34a}',
      '[data-theme="dark"] .seq-actor-tag.cloud{background:#0d2240;color:#60a5fa}',
      '[data-theme="dark"] .seq-actor-tag.service{background:rgba(163,113,247,.15);color:#c4a5fb}',
      '[data-theme="dark"] .seq-actor-tag.external{background:#3b0a0a;color:#f87171}',
      '[data-theme="dark"] .seq-actor-tag.onprem{background:#052e16;color:#4ade80}',

      /* ── Body Grid + Lifelines ── */
      '.seq-body{display:grid;position:relative;min-height:120px}',
      '.seq-lifeline{position:relative}',
      '.seq-lifeline::before{content:"";position:absolute;left:50%;top:0;bottom:0;width:2px;background:repeating-linear-gradient(to bottom,var(--seq-lifeline) 0px,var(--seq-lifeline) 6px,transparent 6px,transparent 12px);transform:translateX(-1px)}',

      /* ── Messages Overlay ── */
      '.seq-messages{position:absolute;top:0;left:0;right:0;z-index:5}',
      '.seq-msg{position:relative;opacity:0;transform:translateY(8px);transition:opacity .5s ease,transform .5s ease}',
      '.seq-msg.visible{opacity:1;transform:translateY(0)}',
      '.seq-msg.active{background:var(--seq-highlight);border-radius:6px}',
      '.seq-msg.clickable{cursor:pointer}',
      '.seq-msg.clickable:hover{background:var(--seq-highlight);border-radius:4px}',

      /* ── Separators ── */
      '.seq-sep{position:relative;height:28px;display:flex;align-items:center;justify-content:center}',
      '.seq-sep-label{font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:var(--text-secondary,#8B949E);background:var(--bg-card,#1C2128);padding:0 8px;position:relative;z-index:2}',
      '.seq-sep::before{content:"";position:absolute;left:5%;right:5%;top:50%;height:1px;background:var(--border-primary,#30363D)}',

      /* ── Arrows ── */
      '.seq-arrow{position:absolute;height:2px;top:14px;background:var(--seq-arrow-rest);transition:background .4s}',
      '.seq-msg.active .seq-arrow,.seq-msg.visible .seq-arrow{background:var(--seq-arrow-active)}',
      '.seq-arrow::after{content:"";position:absolute;right:-1px;top:-5px;border:6px solid transparent;border-left-color:var(--seq-arrow-rest);transition:border-color .4s}',
      '.seq-msg.active .seq-arrow::after,.seq-msg.visible .seq-arrow::after{border-left-color:var(--seq-arrow-active)}',
      '.seq-arrow.reverse::after{right:auto;left:-1px;border-left-color:transparent;border-right-color:var(--seq-arrow-rest)}',
      '.seq-msg.active .seq-arrow.reverse::after,.seq-msg.visible .seq-arrow.reverse::after{border-left-color:transparent;border-right-color:var(--seq-arrow-active)}',
      '.seq-arrow.self{height:16px;border-top:2px solid var(--seq-arrow-rest);border-right:2px solid var(--seq-arrow-rest);border-bottom:2px solid var(--seq-arrow-rest);border-radius:0 4px 4px 0;background:none!important;top:6px}',
      '.seq-msg.active .seq-arrow.self,.seq-msg.visible .seq-arrow.self{border-color:var(--seq-arrow-active)}',

      /* ── Arrow Label ── */
      '.seq-arrow-label{position:absolute;top:-12px;left:50%;transform:translateX(-50%);font-size:.55rem;font-weight:600;color:var(--text-secondary,#8B949E);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:90%;background:var(--bg-card,#1C2128);padding:0 3px;transition:color .4s}',
      '.seq-msg.active .seq-arrow-label{color:var(--seq-arrow-active)}',

      /* ── Step Number Circle ── */
      '.seq-msg-num{position:absolute;left:4px;top:6px;width:16px;height:16px;border-radius:50%;background:var(--seq-arrow-rest);color:#fff;font-size:.55rem;font-weight:700;display:flex;align-items:center;justify-content:center;transition:background .4s}',
      '.seq-msg.active .seq-msg-num{background:var(--seq-arrow-active)}',

      /* ── Dash Flow Animation (V3.1) ── */
      '@keyframes seqDashFlow{to{background-position:20px 0}}',
      '.seq-msg.active .seq-arrow:not(.self){background:repeating-linear-gradient(90deg,var(--seq-arrow-active) 0px,var(--seq-arrow-active) 8px,transparent 8px,transparent 14px);background-size:20px 2px;animation:seqDashFlow .6s linear infinite}',
      '.seq-msg.active .seq-arrow.reverse{animation-direction:reverse}',

      /* ── Explain Panel ── */
      '.seq-explain{padding:8px 12px;background:var(--bg-card,#1C2128);border:1px solid var(--border-primary,#30363D);border-left:3px solid var(--seq-arrow-active);border-radius:0 8px 8px 0;box-shadow:0 1px 4px rgba(0,0,0,.12);transition:all .3s}',
      '.seq-explain-num{font-size:.65rem;font-weight:700;color:var(--seq-arrow-active);text-transform:uppercase;letter-spacing:.4px;margin-bottom:2px}',
      '.seq-explain-title{font-size:.9rem;font-weight:700;margin-bottom:3px}',
      '.seq-explain-desc{font-size:.78rem;color:var(--text-secondary,#8B949E);line-height:1.45}',
      '.seq-explain-desc code{background:rgba(110,118,129,.2);padding:0 3px;border-radius:3px;font-size:.65rem}',
      '.seq-explain-flow{display:flex;align-items:center;gap:4px;margin-top:4px;font-size:.65rem;color:var(--text-secondary,#8B949E)}',
      '.seq-explain-flow .from,.seq-explain-flow .to{font-weight:600;color:var(--text-primary,#E6EDF3)}',
      '.seq-explain-flow .arrow-icon{color:var(--seq-arrow-active)}',
      '.seq-explain-link{margin-top:6px}',
      '.seq-explain-link a{display:inline-flex;align-items:center;gap:4px;font-size:.7rem;font-weight:600;color:var(--seq-arrow-active);text-decoration:none;cursor:pointer;padding:3px 8px;border:1px solid var(--seq-arrow-active);border-radius:4px;transition:background .15s,color .15s}',
      '.seq-explain-link a:hover{background:var(--seq-arrow-active);color:#fff}',

      /* ── Show All Stacked Cards ── */
      '.seq-explain-all{display:flex;flex-direction:column;gap:5px}',
      '.seq-explain-all-item{padding:6px 10px;background:var(--bg-card,#1C2128);border:1px solid var(--border-primary,#30363D);border-left:3px solid var(--seq-arrow-active);border-radius:0 6px 6px 0;transition:border-color .2s}',
      '.seq-explain-all-item:hover{border-color:var(--seq-arrow-active)}',
      '.seq-explain-all-item .step-num{font-size:.58rem;font-weight:700;color:var(--seq-arrow-active);text-transform:uppercase;letter-spacing:.3px;margin-bottom:1px}',
      '.seq-explain-all-item .step-title{font-size:.75rem;font-weight:700;margin-bottom:1px}',
      '.seq-explain-all-item .step-desc{font-size:.68rem;color:var(--text-secondary,#8B949E);line-height:1.35}',
      '.seq-explain-all-item .step-desc code{background:rgba(110,118,129,.2);padding:0 2px;border-radius:2px;font-size:.58rem}',
      '.seq-explain-all-item .step-flow{display:flex;align-items:center;gap:3px;margin-top:2px;font-size:.55rem;color:var(--text-secondary,#8B949E)}',
      '.seq-explain-all-item .step-flow .from,.seq-explain-all-item .step-flow .to{font-weight:600;color:var(--text-primary,#E6EDF3)}',
      '.seq-explain-all-item .step-flow .arrow-icon{color:var(--seq-arrow-active)}',
      '.seq-explain-all-item .step-link{margin-top:3px}',
      '.seq-explain-all-item .step-link a{font-size:.6rem;font-weight:600;color:var(--seq-arrow-active);text-decoration:none;cursor:pointer}',
      '.seq-explain-all-item .step-link a:hover{text-decoration:underline}',

      /* ── View Details Button ── */
      '.seq-detail-btn{display:inline-flex;align-items:center;gap:3px;font-size:.65rem;font-weight:600;color:var(--seq-arrow-active);background:transparent;border:1px solid var(--seq-arrow-active);border-radius:4px;padding:3px 8px;cursor:pointer;transition:all .15s;margin-top:5px;font-family:inherit}',
      '.seq-detail-btn:hover{background:var(--seq-arrow-active);color:#fff}',
      '.seq-explain-all-item .seq-detail-btn{font-size:.58rem;padding:2px 6px;margin-top:3px}',

      /* ── Step Detail Modal ── */
      '.seq-modal-overlay{display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.55);align-items:center;justify-content:center}',
      '.seq-modal-overlay.open{display:flex}',
      '[data-theme="dark"] .seq-modal-overlay{background:rgba(0,0,0,.72)}',
      '.seq-modal{background:var(--bg-card,#1C2128);color:var(--text-primary,#E6EDF3);border:1px solid var(--border-primary,#30363D);border-radius:12px;width:min(720px,92vw);max-height:85vh;overflow-y:auto;border-top:3px solid var(--seq-arrow-active);box-shadow:0 4px 8px rgba(0,0,0,.2),0 12px 28px rgba(0,0,0,.35)}',
      '[data-theme="light"] .seq-modal{background:var(--bg-card,#fff);color:var(--text-primary,#1F2328);box-shadow:0 4px 12px rgba(0,0,0,.1),0 12px 28px rgba(0,0,0,.15)}',
      '.seq-modal-header{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;border-bottom:1px solid var(--border-primary,#30363D);position:sticky;top:0;background:var(--bg-card,#1C2128);z-index:1;border-radius:12px 12px 0 0}',
      '[data-theme="light"] .seq-modal-header{background:var(--bg-card,#fff)}',
      '.seq-modal-header h3{margin:0;font-size:.95rem;font-weight:700}',
      '.seq-modal-badge{font-size:.6rem;font-weight:700;color:#fff;background:var(--seq-arrow-active);padding:2px 8px;border-radius:10px;margin-right:8px}',
      '.seq-modal-close{background:none;border:none;font-size:1.3rem;cursor:pointer;color:var(--text-secondary,#8B949E);padding:0 4px;line-height:1;font-family:inherit}',
      '.seq-modal-close:hover{color:var(--text-primary,#E6EDF3)}',
      '.seq-modal-body{padding:16px 18px}',
      '.seq-modal-flow{display:flex;align-items:center;gap:6px;padding:8px 12px;background:var(--bg-inset,#0D1117);border:1px solid var(--border-primary,#30363D);border-radius:8px;margin-bottom:12px;font-size:.78rem}',
      '[data-theme="light"] .seq-modal-flow{background:var(--bg-inset,#F0F2F5)}',
      '.seq-modal-flow .mf-actor{font-weight:700;color:var(--text-primary,#E6EDF3)}',
      '.seq-modal-flow .mf-arrow{color:var(--seq-arrow-active);font-size:1rem}',
      '.seq-modal-flow .mf-label{font-size:.7rem;color:var(--text-secondary,#8B949E);margin-left:auto;font-style:italic;max-width:50%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
      '.seq-modal-section{margin-bottom:14px}',
      '.seq-modal-section h4{font-size:.82rem;font-weight:700;color:var(--seq-arrow-active);margin:0 0 4px;text-transform:uppercase;letter-spacing:.3px}',
      '.seq-modal-section p{font-size:.82rem;color:var(--text-secondary,#8B949E);line-height:1.55;margin:0 0 6px}',
      '.seq-modal-section ul{margin:4px 0 0 18px;font-size:.78rem;color:var(--text-secondary,#8B949E);line-height:1.5}',
      '.seq-modal-section li{margin-bottom:3px}',
      '.seq-modal-section code{background:rgba(110,118,129,.2);padding:1px 4px;border-radius:3px;font-size:.7rem}',
      '.seq-modal-section strong{color:var(--text-primary,#E6EDF3)}',

      /* ── Width Control ── */
      '.seq-width-control{display:inline-flex;align-items:center;gap:3px;white-space:nowrap;margin-left:auto}',
      '.seq-width-btn{border:1px solid var(--border-primary,#30363D);background:transparent;color:var(--text-secondary,#8B949E);width:24px;height:24px;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:700;display:inline-flex;align-items:center;justify-content:center;transition:all .2s;font-family:inherit;line-height:1}',
      '.seq-width-btn:hover{border-color:var(--accent-cyan,#39D2C0);color:var(--accent-cyan,#39D2C0)}',
      '.seq-width-btn:disabled{opacity:.3;cursor:not-allowed}',
      '.seq-width-label{min-width:36px;text-align:center;font-weight:600;color:var(--text-primary,#E6EDF3);font-size:.7rem}',
    ].join('\n');
    document.head.appendChild(s);
  }

  /* ══════════════════════════════════════════════════════════════
     Mermaid Source Parser
     ══════════════════════════════════════════════════════════════ */
  function parseMermaid(src) {
    var lines = src.split('\n').map(function (l) { return l.trim(); }).filter(Boolean);
    var participants = [];
    var pMap = {};
    var steps = [];
    var separators = [];

    lines.forEach(function (line) {
      /* participant / actor declarations */
      var pMatch = line.match(/^(?:participant|actor)\s+(\S+?)(?:\s+as\s+(.+))?$/i);
      if (pMatch) {
        var id = pMatch[1];
        var alias = pMatch[2] ? pMatch[2].replace(/<br\/?>/gi, ' ').replace(/\(.+?\)/g, '').trim() : id;
        if (!pMap.hasOwnProperty(id)) {
          pMap[id] = participants.length;
          participants.push({ id: id, name: alias });
        }
        return;
      }
      /* Messages: A->>B: label, A-->>B: label, A-)B: label, etc. */
      var mMatch = line.match(/^(\S+?)\s*(-[->x.]+[>)]+[+-]?)\s*(\S+?)\s*:\s*(.+)$/);
      if (mMatch) {
        var fromId = mMatch[1];
        var toId = mMatch[3];
        var label = mMatch[4].replace(/<br\/?>/gi, ' ').trim();
        if (!pMap.hasOwnProperty(fromId)) { pMap[fromId] = participants.length; participants.push({ id: fromId, name: fromId }); }
        if (!pMap.hasOwnProperty(toId)) { pMap[toId] = participants.length; participants.push({ id: toId, name: toId }); }
        steps.push({ from: pMap[fromId], to: pMap[toId], label: label, isResponse: mMatch[2].indexOf('--') >= 0 });
        return;
      }
      /* Structural: loop / alt / else / rect / break / critical / opt / par / and */
      var sMatch = line.match(/^(loop|alt|else|rect|break|critical|opt|par|and)\b\s*(.*)/i);
      if (sMatch) {
        separators.push({ after: steps.length, label: sMatch[1].toUpperCase() + (sMatch[2] ? ' ' + sMatch[2].replace(/<br\/?>/g, ' ') : '') });
      }
    });

    return { participants: participants, steps: steps, separators: separators };
  }

  /* ══════════════════════════════════════════════════════════════
     Extract Step Explanations from Adjacent HTML
     ══════════════════════════════════════════════════════════════ */
  function extractExplanations(container) {
    var explDiv = container.querySelector('.diagram-explanation');
    if (!explDiv) {
      var sib = container.nextElementSibling;
      for (var i = 0; i < 3 && sib; i++) {
        if (sib.classList && sib.classList.contains('diagram-explanation')) { explDiv = sib; break; }
        if (sib.classList && (sib.classList.contains('diagram-container') || sib.classList.contains('seq-sim-section'))) break;
        if (sib.tagName === 'H2' || sib.tagName === 'H3') break;
        sib = sib.nextElementSibling;
      }
    }
    if (!explDiv) return [];
    var items = explDiv.querySelectorAll('li');
    var result = [];
    items.forEach(function (li) {
      var strong = li.querySelector('strong');
      var title = strong ? strong.textContent.trim() : '';
      var desc = li.innerHTML;
      if (strong) desc = desc.replace(strong.outerHTML, '').replace(/^[\s\u2014:\-\u2013]+/, '');
      result.push({ title: title, desc: desc.trim() });
    });
    explDiv.style.display = 'none';
    return result;
  }

  /* ══════════════════════════════════════════════════════════════
     Icon & Tag Pickers (heuristic)
     ══════════════════════════════════════════════════════════════ */
  function pickIcon(name) {
    var n = name.toLowerCase();
    if (n.indexOf('user') >= 0 || n.indexOf('actor') >= 0) return '\uD83D\uDC64';
    if (n.indexOf('agent') >= 0) return '\uD83E\uDD16';
    if (n.indexOf('cli') >= 0 || n.indexOf('runner') >= 0 || n.indexOf('entry') >= 0 || n.indexOf('pipeline') >= 0) return '\u2328\uFE0F';
    if (n.indexOf('config') >= 0) return '\u2699\uFE0F';
    if (n.indexOf('auth') >= 0 || n.indexOf('credential') >= 0 || n.indexOf('identity') >= 0) return '\uD83D\uDD10';
    if (n.indexOf('graph') >= 0 && n.indexOf('api') >= 0) return '\uD83C\uDF10';
    if (n.indexOf('graph') >= 0) return '\uD83D\uDCCA';
    if (n.indexOf('orchestrat') >= 0) return '\uD83C\uDFAF';
    if (n.indexOf('registry') >= 0) return '\uD83D\uDCCB';
    if (n.indexOf('inventory') >= 0) return '\uD83D\uDCE6';
    if (n.indexOf('collector') >= 0 || n.indexOf('azure coll') >= 0 || n.indexOf('entra coll') >= 0) return '\uD83D\uDD0D';
    if (n.indexOf('arm') >= 0 || n.indexOf('azure') >= 0 || n.indexOf('subscription') >= 0) return '\u2601\uFE0F';
    if (n.indexOf('entra') >= 0) return '\uD83D\uDEE1\uFE0F';
    if (n.indexOf('engine') >= 0 || n.indexOf('eval') >= 0 || n.indexOf('scoring') >= 0 || n.indexOf('score') >= 0) return '\u2696\uFE0F';
    if (n.indexOf('domain') >= 0) return '\uD83C\uDFDB\uFE0F';
    if (n.indexOf('framework') >= 0 || n.indexOf('mapping') >= 0) return '\uD83D\uDCD0';
    if (n.indexOf('report') >= 0 || n.indexOf('generator') >= 0) return '\uD83D\uDCC4';
    if (n.indexOf('file') >= 0 || n.indexOf('system') >= 0) return '\uD83D\uDCBE';
    if (n.indexOf('suppress') >= 0) return '\uD83D\uDD07';
    if (n.indexOf('plugin') >= 0) return '\uD83E\uDDE9';
    if (n.indexOf('cross') >= 0 || n.indexOf('fallback') >= 0) return '\uD83D\uDD00';
    if (n.indexOf('checkpoint') >= 0) return '\uD83D\uDCBE';
    if (n.indexOf('index') >= 0 || n.indexOf('evidence') >= 0) return '\uD83D\uDCD1';
    if (n.indexOf('result') >= 0) return '\u2705';
    if (n.indexOf('api') >= 0) return '\uD83C\uDF10';
    if (n.indexOf('paginate') >= 0) return '\uD83D\uDCDC';
    if (n.indexOf('make_evidence') >= 0) return '\uD83C\uDFED';
    if (n.indexOf('sha') >= 0 || n.indexOf('hash') >= 0 || n.indexOf('determinism') >= 0) return '\uD83D\uDD12';
    return '\u2B21';
  }

  function pickTag(name) {
    var n = name.toLowerCase();
    if (n.indexOf('azure') >= 0 || n.indexOf('arm') >= 0 || n.indexOf('cloud') >= 0 || n.indexOf('graph') >= 0 || n.indexOf('api') >= 0 || n.indexOf('subscription') >= 0) return { text: 'Cloud', type: 'cloud' };
    if (n.indexOf('entra') >= 0 || n.indexOf('identity') >= 0) return { text: 'Identity', type: 'cloud' };
    if (n.indexOf('engine') >= 0 || n.indexOf('eval') >= 0 || n.indexOf('scoring') >= 0 || n.indexOf('score') >= 0 || n.indexOf('orchestrat') >= 0) return { text: 'Engine', type: 'engine' };
    if (n.indexOf('user') >= 0 || n.indexOf('actor') >= 0) return { text: 'External', type: 'external' };
    if (n.indexOf('collector') >= 0 || n.indexOf('registry') >= 0 || n.indexOf('inventory') >= 0) return { text: 'Service', type: 'service' };
    if (n.indexOf('framework') >= 0 || n.indexOf('mapping') >= 0 || n.indexOf('evidence') >= 0 || n.indexOf('index') >= 0) return { text: 'Data', type: 'data' };
    if (n.indexOf('report') >= 0 || n.indexOf('file') >= 0 || n.indexOf('checkpoint') >= 0) return { text: 'Data', type: 'data' };
    return { text: 'Service', type: 'service' };
  }

  /* ══════════════════════════════════════════════════════════════
     Step Detail Modal — Singleton, reused across all diagrams
     ══════════════════════════════════════════════════════════════ */
  var modalOverlay = null;
  var modalTitle = null;
  var modalBody = null;

  function ensureModal() {
    if (modalOverlay) return;
    modalOverlay = document.createElement('div');
    modalOverlay.className = 'seq-modal-overlay';
    modalOverlay.innerHTML =
      '<div class="seq-modal">' +
        '<div class="seq-modal-header">' +
          '<h3 id="seq-modal-title">Step Details</h3>' +
          '<button class="seq-modal-close" id="seq-modal-close" title="Close">&times;</button>' +
        '</div>' +
        '<div class="seq-modal-body" id="seq-modal-body"></div>' +
      '</div>';
    document.body.appendChild(modalOverlay);
    modalTitle = document.getElementById('seq-modal-title');
    modalBody = document.getElementById('seq-modal-body');
    document.getElementById('seq-modal-close').addEventListener('click', closeModal);
    modalOverlay.addEventListener('click', function (e) { if (e.target === modalOverlay) closeModal(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && modalOverlay.classList.contains('open')) closeModal(); });
  }

  function closeModal() {
    if (modalOverlay) modalOverlay.classList.remove('open');
  }

  function showDetailModal(step, actors, stepIdx, totalSteps) {
    ensureModal();
    var fromName = actors[step.from] || 'Source';
    var toName = actors[step.to] || 'Target';
    var title = step.title || step.label;
    var arrowSymbol = step.from === step.to ? '\u21BB' : (step.to > step.from ? '\u2192' : '\u2190');

    modalTitle.innerHTML = '<span class="seq-modal-badge">Step ' + (stepIdx + 1) + '</span>' + title;

    var flowHtml =
      '<div class="seq-modal-flow">' +
        '<span class="mf-actor">' + fromName + '</span>' +
        '<span class="mf-arrow">' + arrowSymbol + '</span>' +
        '<span class="mf-actor">' + toName + '</span>' +
        '<span class="mf-label">' + step.label + '</span>' +
      '</div>';

    var bodyHtml = flowHtml;

    /* Rich details from data-seq-details */
    if (step.details) {
      var d = step.details;
      if (d.overview) {
        bodyHtml += '<div class="seq-modal-section"><h4>\uD83D\uDCD6 Overview</h4><p>' + d.overview + '</p></div>';
      }
      if (d.dataFlow) {
        bodyHtml += '<div class="seq-modal-section"><h4>\uD83D\uDD04 Data Flow</h4><p>' + d.dataFlow + '</p></div>';
      }
      if (d.keyPoints && d.keyPoints.length) {
        bodyHtml += '<div class="seq-modal-section"><h4>\u2B50 Key Points</h4><ul>';
        d.keyPoints.forEach(function (kp) { bodyHtml += '<li>' + kp + '</li>'; });
        bodyHtml += '</ul></div>';
      }
      if (d.whyItMatters) {
        bodyHtml += '<div class="seq-modal-section"><h4>\u26A1 Why This Matters</h4><p>' + d.whyItMatters + '</p></div>';
      }
      if (d.output) {
        bodyHtml += '<div class="seq-modal-section"><h4>\uD83D\uDCE4 Output</h4><p>' + d.output + '</p></div>';
      }
    } else {
      /* Auto-generate from available info */
      var descHtml = step.desc || step.label;
      bodyHtml += '<div class="seq-modal-section"><h4>\uD83D\uDCD6 Overview</h4><p>' + descHtml + '</p></div>';
      bodyHtml += '<div class="seq-modal-section"><h4>\uD83D\uDD04 Data Flow</h4><p>';
      if (step.from === step.to) {
        bodyHtml += '<strong>' + fromName + '</strong> performs an internal operation: <em>' + step.label + '</em>.';
      } else {
        bodyHtml += '<strong>' + fromName + '</strong> sends a message to <strong>' + toName + '</strong>: <em>' + step.label + '</em>.';
      }
      bodyHtml += '</p></div>';
    }

    bodyHtml += '<div class="seq-modal-section" style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border-primary,#30363D);font-size:.7rem;color:var(--text-muted,#6E7681)">' +
      'Step ' + (stepIdx + 1) + ' of ' + totalSteps + '</div>';

    modalBody.innerHTML = bodyHtml;
    modalOverlay.classList.add('open');
  }

  /* ══════════════════════════════════════════════════════════════
     initSeqDiagram(cfg) — V3.1-Style Reusable Animated Engine

     cfg = {
       colCenters:   [10, 30, 50, 70, 90],     // % positions per actor
       actors:       ['Name1', 'Name2', ...],   // display names
       steps:        [{from, to, label, title, desc}, ...],
       defaultDesc:  'Intro text...',
       messagesId, bodyId, indicatorId,
       explainColId, explainId,
       exNumId, exTitleId, exDescId, exFlowId,
       exLinkId,                                // optional
       playId, prevId, nextId, resetId, showAllId,
       onStepLink:   function(idx){ ... }       // optional
     }
     ══════════════════════════════════════════════════════════════ */
  function initSeqDiagram(cfg) {
    var COL = cfg.colCenters;
    var ACTORS = cfg.actors;
    var STEPS = cfg.steps;

    var msgContainer = document.getElementById(cfg.messagesId);
    var seqBody = document.getElementById(cfg.bodyId);
    var indicator = document.getElementById(cfg.indicatorId);
    var explainCol = document.getElementById(cfg.explainColId);
    var explainPanel = document.getElementById(cfg.explainId);
    var explainNum = document.getElementById(cfg.exNumId);
    var explainTitle = document.getElementById(cfg.exTitleId);
    var explainDesc = document.getElementById(cfg.exDescId);
    var explainFlow = document.getElementById(cfg.exFlowId);
    var linkEl = cfg.exLinkId ? document.getElementById(cfg.exLinkId) : null;
    var btnPlay = document.getElementById(cfg.playId);
    var btnPrev = document.getElementById(cfg.prevId);
    var btnNext = document.getElementById(cfg.nextId);
    var btnReset = document.getElementById(cfg.resetId);
    var btnShowAll = document.getElementById(cfg.showAllId);

    if (!msgContainer || !seqBody || !btnPlay) return null;

    var currentStep = 0;
    var playInterval = null;
    var ROW_HEIGHT = 34;
    var allContainer = null;
    var defaultDesc = cfg.defaultDesc || 'Step through the sequence to see each interaction in detail.';

    /* ── Build message rows ── */
    function buildMessages() {
      msgContainer.innerHTML = '';
      var sepIdx = 0;
      var seps = cfg.separators || [];
      STEPS.forEach(function (s, i) {
        while (sepIdx < seps.length && seps[sepIdx].after === i) {
          var sep = document.createElement('div');
          sep.className = 'seq-sep';
          sep.innerHTML = '<span class="seq-sep-label">' + seps[sepIdx].label + '</span>';
          msgContainer.appendChild(sep);
          sepIdx++;
        }
        var row = document.createElement('div');
        row.className = 'seq-msg';
        row.setAttribute('data-step', i + 1);
        row.style.height = ROW_HEIGHT + 'px';
        row.style.position = 'relative';

        var num = document.createElement('div');
        num.className = 'seq-msg-num';
        num.textContent = i + 1;
        row.appendChild(num);

        var arrow = document.createElement('div');
        var fromPct = COL[s.from];
        var toPct = COL[s.to];
        var isSelf = s.from === s.to;
        var isReverse = s.to < s.from;

        if (isSelf) {
          arrow.className = 'seq-arrow self';
          arrow.style.left = fromPct + '%';
          arrow.style.width = '8%';
        } else if (isReverse) {
          arrow.className = 'seq-arrow reverse';
          arrow.style.left = toPct + '%';
          arrow.style.width = (fromPct - toPct) + '%';
        } else {
          arrow.className = 'seq-arrow';
          arrow.style.left = fromPct + '%';
          arrow.style.width = (toPct - fromPct) + '%';
        }

        var lbl = document.createElement('div');
        lbl.className = 'seq-arrow-label';
        lbl.textContent = s.label.length > 60 ? s.label.substring(0, 57) + '...' : s.label;
        lbl.title = s.label;
        if (isSelf) { lbl.style.left = '110%'; lbl.style.transform = 'none'; lbl.style.top = '2px'; }
        arrow.appendChild(lbl);
        row.appendChild(arrow);
        msgContainer.appendChild(row);
      });
      /* Trailing separators */
      while (sepIdx < seps.length) {
        var sep2 = document.createElement('div');
        sep2.className = 'seq-sep';
        sep2.innerHTML = '<span class="seq-sep-label">' + seps[sepIdx].label + '</span>';
        msgContainer.appendChild(sep2);
        sepIdx++;
      }
      seqBody.style.minHeight = (STEPS.length * ROW_HEIGHT + (seps.length * 28) + 20) + 'px';
    }

    /* ── Update explanation panel ── */
    function updateExplain(stepIdx) {
      if (stepIdx <= 0) {
        explainNum.textContent = 'Getting Started';
        explainTitle.textContent = 'Click Play or Next to begin';
        explainDesc.innerHTML = defaultDesc;
        explainFlow.innerHTML = '';
        if (linkEl) linkEl.innerHTML = '';
        return;
      }
      var s = STEPS[stepIdx - 1];
      explainNum.textContent = 'Step ' + stepIdx + ' of ' + STEPS.length;
      explainTitle.textContent = s.title || s.label;
      explainDesc.innerHTML = s.desc || s.label;
      var arrowHtml = s.from === s.to ? ' &#8635; ' : (s.to > s.from ? ' &#8594; ' : ' &#8592; ');
      explainFlow.innerHTML =
        '<span class="from">' + ACTORS[s.from] + '</span>' +
        '<span class="arrow-icon">' + arrowHtml + '</span>' +
        '<span class="to">' + ACTORS[s.to] + '</span>';
      /* View Details button */
      var detailBtnContainer = explainPanel.querySelector('.seq-detail-wrap');
      if (!detailBtnContainer) {
        detailBtnContainer = document.createElement('div');
        detailBtnContainer.className = 'seq-detail-wrap';
        explainPanel.appendChild(detailBtnContainer);
      }
      detailBtnContainer.innerHTML = '<button class="seq-detail-btn" data-step-idx="' + (stepIdx - 1) + '">View Details \u2192</button>';
      detailBtnContainer.querySelector('.seq-detail-btn').addEventListener('click', function () {
        showDetailModal(s, ACTORS, stepIdx - 1, STEPS.length);
      });
      if (linkEl && cfg.onStepLink) {
        linkEl.innerHTML = cfg.onStepLink(stepIdx - 1) || '';
      } else if (linkEl) {
        linkEl.innerHTML = '';
      }
    }

    /* ── Show All helpers ── */
    function hideAllExplains() {
      if (allContainer) { allContainer.remove(); allContainer = null; }
      explainPanel.style.display = '';
    }

    function showAllExplains() {
      explainPanel.style.display = 'none';
      if (allContainer) allContainer.remove();
      allContainer = document.createElement('div');
      allContainer.className = 'seq-explain-all';
      STEPS.forEach(function (s, i) {
        var item = document.createElement('div');
        item.className = 'seq-explain-all-item';
        var arrowHtml = s.from === s.to ? ' &#8635; ' : (s.to > s.from ? ' &#8594; ' : ' &#8592; ');
        var linkHtml = '';
        if (cfg.onStepLink) {
          linkHtml = cfg.onStepLink(i) || '';
          if (linkHtml) linkHtml = '<div class="step-link">' + linkHtml + '</div>';
        }
        var detailBtn = '<button class="seq-detail-btn" data-all-step="' + i + '">View Details \u2192</button>';
        item.innerHTML =
          '<div class="step-num">Step ' + (i + 1) + ' of ' + STEPS.length + '</div>' +
          '<div class="step-title">' + (s.title || s.label) + '</div>' +
          '<div class="step-desc">' + (s.desc || s.label) + '</div>' +
          '<div class="step-flow">' +
            '<span class="from">' + ACTORS[s.from] + '</span>' +
            '<span class="arrow-icon">' + arrowHtml + '</span>' +
            '<span class="to">' + ACTORS[s.to] + '</span>' +
          '</div>' + linkHtml + detailBtn;
        (function (stepRef, idx) {
          item.querySelector('.seq-detail-btn').addEventListener('click', function () {
            showDetailModal(stepRef, ACTORS, idx, STEPS.length);
          });
        })(s, i);
        allContainer.appendChild(item);
      });
      explainCol.appendChild(allContainer);
    }

    /* ── Navigation ── */
    function goToStep(n) {
      hideAllExplains();
      currentStep = Math.max(0, Math.min(STEPS.length, n));
      var rows = msgContainer.querySelectorAll('.seq-msg');
      rows.forEach(function (row, i) {
        row.classList.remove('active', 'visible');
        if (i < currentStep) row.classList.add('visible');
        if (i === currentStep - 1) row.classList.add('active');
      });
      indicator.textContent = 'Step ' + currentStep + ' / ' + STEPS.length;
      btnPrev.disabled = currentStep <= 0;
      btnNext.disabled = currentStep >= STEPS.length;
      updateExplain(currentStep);
      if (currentStep > 0) {
        var activeRow = msgContainer.querySelector('.seq-msg.active');
        if (activeRow) activeRow.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }

    function showAll() {
      stopPlay();
      currentStep = STEPS.length;
      var rows = msgContainer.querySelectorAll('.seq-msg');
      rows.forEach(function (r) { r.classList.add('visible'); r.classList.remove('active'); });
      if (rows.length) rows[rows.length - 1].classList.add('active');
      indicator.textContent = 'All ' + STEPS.length + ' steps shown';
      btnPrev.disabled = false;
      btnNext.disabled = true;
      showAllExplains();
    }

    /* ── Playback ── */
    function stopPlay() {
      if (playInterval) { clearInterval(playInterval); playInterval = null; }
      btnPlay.innerHTML = '&#9654; Play';
    }

    function startPlay() {
      if (currentStep >= STEPS.length) goToStep(0);
      btnPlay.innerHTML = '&#9646;&#9646; Pause';
      playInterval = setInterval(function () {
        if (currentStep >= STEPS.length) { stopPlay(); return; }
        goToStep(currentStep + 1);
      }, 2200);
    }

    /* ── Wire controls ── */
    btnPlay.addEventListener('click', function () { playInterval ? stopPlay() : startPlay(); });
    btnNext.addEventListener('click', function () { stopPlay(); goToStep(currentStep + 1); });
    btnPrev.addEventListener('click', function () { stopPlay(); goToStep(currentStep - 1); });
    btnReset.addEventListener('click', function () { stopPlay(); goToStep(0); });
    btnShowAll.addEventListener('click', showAll);

    buildMessages();
    showAll();

    return { goToStep: goToStep, showAll: showAll, startPlay: startPlay, stopPlay: stopPlay };
  }

  /* ══════════════════════════════════════════════════════════════
     createSimDiagram — Auto-build HTML & wire initSeqDiagram
     Used by enhanceAll() when replacing Mermaid source blocks
     ══════════════════════════════════════════════════════════════ */
  var diagramCounter = 0;

  function createSimDiagram(wrapperEl, parsed, explanations, sectionTitle, detailsData) {
    diagramCounter++;
    var P = 'sd' + diagramCounter;
    var actors = parsed.participants;
    var steps = parsed.steps;
    var N = actors.length;

    /* Compute even column centers */
    var COL = [];
    for (var c = 0; c < N; c++) COL.push(((c + 0.5) / N) * 100);

    /* Merge explanations + rich details into steps config */
    var cfgSteps = steps.map(function (st, i) {
      var cfg = {
        from: st.from,
        to: st.to,
        label: st.label,
        title: (explanations[i] && explanations[i].title) || st.label,
        desc: (explanations[i] && explanations[i].desc) || ''
      };
      if (detailsData && detailsData[i]) {
        cfg.details = detailsData[i];
      }
      return cfg;
    });

    var actorNames = actors.map(function (a) { return a.name; });

    /* Build actor HTML */
    var actorsHtml = actors.map(function (a) {
      var tag = pickTag(a.name);
      return '<div class="seq-actor">' +
        '<div class="seq-actor-icon">' + pickIcon(a.name) + '</div>' +
        '<div class="seq-actor-name">' + a.name + '</div>' +
        '<span class="seq-actor-tag ' + tag.type + '">' + tag.text + '</span>' +
        '</div>';
    }).join('');

    var lifelines = '';
    for (var i = 0; i < N; i++) lifelines += '<div class="seq-lifeline"></div>';

    /* Assemble section */
    var section = document.createElement('div');
    section.className = 'seq-sim-section';
    section.innerHTML =
      (sectionTitle ? '<h3 class="seq-title">' + sectionTitle + '</h3>' : '') +
      '<div class="seq-controls" role="toolbar">' +
        '<button class="seq-btn primary" id="' + P + '-play">&#9654; Play</button>' +
        '<button class="seq-btn" id="' + P + '-prev" disabled>&larr; Prev</button>' +
        '<button class="seq-btn" id="' + P + '-next">&rarr; Next</button>' +
        '<button class="seq-btn" id="' + P + '-reset">Reset</button>' +
        '<button class="seq-btn" id="' + P + '-showAll">Show All</button>' +
        '<span class="seq-step-indicator" id="' + P + '-ind">Step 0 / ' + steps.length + '</span>' +
      '</div>' +
      '<div class="seq-layout">' +
        '<div class="seq-diagram-col">' +
          '<div class="seq-actors" style="grid-template-columns:repeat(' + N + ',1fr)">' + actorsHtml + '</div>' +
          '<div class="seq-body" id="' + P + '-body" style="grid-template-columns:repeat(' + N + ',1fr)">' +
            lifelines +
            '<div class="seq-messages" id="' + P + '-msgs"></div>' +
          '</div>' +
        '</div>' +
        '<div class="seq-explain-col" id="' + P + '-exCol">' +
          '<div class="seq-explain" id="' + P + '-ex">' +
            '<div class="seq-explain-num" id="' + P + '-exNum">Getting Started</div>' +
            '<div class="seq-explain-title" id="' + P + '-exTitle">Click Play or Next to begin</div>' +
            '<div class="seq-explain-desc" id="' + P + '-exDesc">Step through the sequence to see each interaction in detail.</div>' +
            '<div class="seq-explain-flow" id="' + P + '-exFlow"></div>' +
          '</div>' +
        '</div>' +
      '</div>';
    wrapperEl.appendChild(section);

    /* Wire via initSeqDiagram */
    return initSeqDiagram({
      colCenters: COL,
      actors: actorNames,
      steps: cfgSteps,
      separators: parsed.separators,
      defaultDesc: 'Step through the sequence to see each interaction in detail.',
      messagesId: P + '-msgs',
      bodyId: P + '-body',
      indicatorId: P + '-ind',
      explainColId: P + '-exCol',
      explainId: P + '-ex',
      exNumId: P + '-exNum',
      exTitleId: P + '-exTitle',
      exDescId: P + '-exDesc',
      exFlowId: P + '-exFlow',
      playId: P + '-play',
      prevId: P + '-prev',
      nextId: P + '-next',
      resetId: P + '-reset',
      showAllId: P + '-showAll'
    });
  }

  /* ══════════════════════════════════════════════════════════════
     enhanceAll — Auto-find Mermaid sequenceDiagrams & replace
     Handles three HTML patterns:
       1. .diagram-container > .mermaid + .diagram-explanation
       2. .seq-viewer > .mermaid + .seq-steps-panel > .seq-step-card
       3. .diagram-container#dc-N > pre.mermaid + .diagram-toolbar
     ══════════════════════════════════════════════════════════════ */
  function enhanceAll() {
    /* Look for pre-captured elements (intercepted before Mermaid ran) */
    var allMermaids = document.querySelectorAll('[data-seq-src]');
    allMermaids.forEach(function (mermaidEl) {
      var src = mermaidEl.getAttribute('data-seq-src') || '';
      if (src.indexOf('sequenceDiagram') < 0) return;

      var mermaidSrc = src.replace(/^\s*sequenceDiagram\s*/, '');
      var parsed = parseMermaid(mermaidSrc);
      if (parsed.steps.length === 0) return;

      /* Read rich details JSON if present */
      var detailsData = null;
      var detailsAttr = mermaidEl.getAttribute('data-seq-details');
      if (detailsAttr) {
        try { detailsData = JSON.parse(detailsAttr); } catch (e) { /* ignore bad JSON */ }
      }

      /* Find the container to hide */
      var hideTarget = mermaidEl.closest('.diagram-container') ||
                       mermaidEl.closest('.seq-viewer') ||
                       mermaidEl.closest('.seq-diagram-wrap') ||
                       mermaidEl.parentElement;

      /* ── Extract explanations ── */
      var explanations = [];

      /* Pattern 1: .diagram-explanation sibling */
      if (hideTarget.classList.contains('diagram-container')) {
        explanations = extractExplanations(hideTarget);
      }

      /* Pattern 2: .seq-step-card elements */
      if (explanations.length === 0) {
        var viewer = mermaidEl.closest('.seq-viewer');
        var stepsPanel = viewer ? viewer.querySelector('.seq-steps-panel') : null;
        if (!stepsPanel) {
          var sib = hideTarget.nextElementSibling;
          while (sib) {
            if (sib.classList && sib.classList.contains('seq-steps-panel')) { stepsPanel = sib; break; }
            if (sib.querySelector && sib.querySelector('.seq-step-card')) { stepsPanel = sib; break; }
            sib = sib.nextElementSibling;
          }
        }
        if (stepsPanel) {
          var cards = stepsPanel.querySelectorAll('.seq-step-card');
          cards.forEach(function (card) {
            var h5 = card.querySelector('h5');
            var p = card.querySelector('p');
            explanations.push({
              title: h5 ? h5.textContent.trim() : '',
              desc: p ? p.innerHTML.trim() : ''
            });
          });
          stepsPanel.style.display = 'none';
        }
      }

      /* If inside .seq-viewer, hide the entire viewer */
      if (hideTarget.closest('.seq-viewer')) {
        hideTarget = hideTarget.closest('.seq-viewer');
      }

      /* Get section title */
      var sectionTitle = '';
      /* Check toolbar-label first */
      var tbLabel = hideTarget.querySelector('.toolbar-label');
      if (tbLabel) {
        sectionTitle = tbLabel.textContent.trim();
      }
      if (!sectionTitle) {
        var walkEl = hideTarget.previousElementSibling;
        for (var w = 0; w < 5 && walkEl; w++) {
          if (/^H[23]$/.test(walkEl.tagName)) { sectionTitle = walkEl.textContent.trim(); break; }
          walkEl = walkEl.previousElementSibling;
        }
      }
      if (!sectionTitle) {
        var parentSection = hideTarget.closest('section');
        if (parentSection) {
          var h2 = parentSection.querySelector('h2');
          if (h2) sectionTitle = h2.textContent.trim().replace(/^\d+\.\s*/, '');
        }
      }

      /* Create replacement */
      var wrapper = document.createElement('div');
      wrapper.className = 'seq-sim-wrapper';
      hideTarget.parentNode.insertBefore(wrapper, hideTarget);
      hideTarget.style.display = 'none';

      createSimDiagram(wrapper, parsed, explanations, sectionTitle, detailsData);
    });
  }

  /* ══════════════════════════════════════════════════════════════
     Width Control — Multi-step 60% to 120% (10% increments)
     Inserted into sticky nav bar of every HTML page
     ══════════════════════════════════════════════════════════════ */
  var WIDTHS = [60, 70, 80, 90, 100, 110, 120];
  var DEFAULT_WIDTH_IDX = 4;
  var widthIdx = DEFAULT_WIDTH_IDX;
  var origMaxWidth = null;

  function applyPageWidth() {
    var pct = WIDTHS[widthIdx];
    var root = document.documentElement;
    if (pct >= 120) {
      /* Full width */
      root.style.setProperty('--max-width', '100%');
    } else if (pct === 100) {
      /* Restore original */
      root.style.setProperty('--max-width', origMaxWidth + 'px');
    } else {
      root.style.setProperty('--max-width', Math.round(origMaxWidth * pct / 100) + 'px');
    }
    var label = document.getElementById('esiq-w-label');
    if (label) label.textContent = pct + '%';
    var minBtn = document.getElementById('esiq-w-minus');
    var plusBtn = document.getElementById('esiq-w-plus');
    if (minBtn) minBtn.disabled = widthIdx <= 0;
    if (plusBtn) plusBtn.disabled = widthIdx >= WIDTHS.length - 1;
    localStorage.setItem('esiq-page-width', String(pct));
  }

  function addWidthControl() {
    /* Find the nav bar — handle all three HTML patterns */
    var nav = document.querySelector('.sticky-nav-inner') ||
              document.querySelector('.sticky-nav .nav-inner') ||
              document.querySelector('.nav-inner') ||
              document.querySelector('.top-nav') ||
              document.querySelector('.sticky-nav') ||
              document.querySelector('nav');
    if (!nav) return;

    /* Capture original --max-width from CSS (before we modify it) */
    var rawVar = getComputedStyle(document.documentElement).getPropertyValue('--max-width');
    if (rawVar && rawVar.trim() && rawVar.trim() !== 'none') {
      origMaxWidth = parseFloat(rawVar);
    }
    if (!origMaxWidth || isNaN(origMaxWidth)) {
      var contentEl = document.querySelector('.container') ||
                      document.querySelector('.slide-inner') ||
                      document.querySelector('main');
      if (contentEl) {
        var computed = getComputedStyle(contentEl).maxWidth;
        origMaxWidth = (computed && computed !== 'none') ? parseFloat(computed) : 1200;
      } else {
        origMaxWidth = 1200;
      }
    }

    /* Build control */
    var ctrl = document.createElement('div');
    ctrl.className = 'seq-width-control';
    ctrl.title = 'Adjust page width (60% \u2013 120%)';
    ctrl.innerHTML =
      '<button class="seq-width-btn" id="esiq-w-minus" title="Narrower">\u2212</button>' +
      '<span class="seq-width-label" id="esiq-w-label">100%</span>' +
      '<button class="seq-width-btn" id="esiq-w-plus" title="Wider">+</button>';

    /* Insert before theme toggle or at end */
    var themeToggle = nav.querySelector('.theme-toggle, .theme-btn, [onclick*="toggleTheme"]');
    if (themeToggle) {
      nav.insertBefore(ctrl, themeToggle);
    } else {
      nav.appendChild(ctrl);
    }

    /* Restore saved width */
    var saved = localStorage.getItem('esiq-page-width');
    if (saved) {
      var savedPct = parseInt(saved, 10);
      var idx = WIDTHS.indexOf(savedPct);
      if (idx >= 0) widthIdx = idx;
    }
    applyPageWidth();

    /* Wire buttons */
    document.getElementById('esiq-w-minus').addEventListener('click', function () {
      if (widthIdx > 0) { widthIdx--; applyPageWidth(); }
    });
    document.getElementById('esiq-w-plus').addEventListener('click', function () {
      if (widthIdx < WIDTHS.length - 1) { widthIdx++; applyPageWidth(); }
    });
  }

  /* ══════════════════════════════════════════════════════════════
     Init on DOM Ready / Load
     ══════════════════════════════════════════════════════════════ */
  function onReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else {
      fn();
    }
  }

  onReady(function () {
    addWidthControl();
  });

  /* Wait for Mermaid render (if present), then enhance */
  window.addEventListener('load', function () {
    setTimeout(enhanceAll, 300);
  });

  /* ══════════════════════════════════════════════════════════════
     PRE-CAPTURE: Intercept Mermaid source BEFORE DOMContentLoaded
     This IIFE runs at script parse time. The <script> tag is placed
     right before </body>, so all DOM elements exist but Mermaid's
     startOnLoad hasn't fired yet. We grab the sequenceDiagram text
     and remove the 'mermaid' class so Mermaid skips those elements.
     ══════════════════════════════════════════════════════════════ */
  (function preCapture() {
    var els = document.querySelectorAll('.mermaid, pre.mermaid');
    els.forEach(function (el) {
      var src = el.textContent || el.innerText || '';
      if (src.indexOf('sequenceDiagram') < 0) return;
      /* Stash the raw source */
      el.setAttribute('data-seq-src', src);
      /* Remove mermaid class so Mermaid.js skips this element */
      el.classList.remove('mermaid');
      el.classList.add('mermaid-seq-captured');
    });
  })();

  /* ── Expose Public API ── */
  window.initSeqDiagram = initSeqDiagram;
  window.createSeqDiagram = createSimDiagram;
  window.parseMermaidSeq = parseMermaid;
})();
