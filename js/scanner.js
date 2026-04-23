/**
 * ShadeParse — scanner.js
 * Main JS audit runner.
 * FIXED: runAudit now calls addHistoryEntry() so source scans appear in history.
 *        Pipeline steps correctly map to detector keys.
 *        updateDashboard called after scan finalization.
 */

'use strict';

/* ─── PIPELINE STEP DEFINITIONS ─── */

var PIPE = [
  { id: 'parse',     name: 'AST Parser',      sub: 'Tokenize & index'  },
  { id: 'vendor',    name: 'Vendor Filter',   sub: 'Skip libraries'    },
  { id: 'secrets',   name: 'Secret Scanner',  sub: 'Keys & tokens'     },
  { id: 'endpoints', name: 'Endpoint Finder', sub: 'Routes & paths'    },
  { id: 'xss',       name: 'DOM XSS / Taint', sub: 'Source to sink'    },
  { id: 'proto',     name: 'Proto Pollution', sub: 'Merge attacks'     },
  { id: 'crypto',    name: 'Weak Crypto',     sub: 'Insecure patterns' },
  { id: 'supply',    name: 'Supply Chain',    sub: 'Dep. risks'        },
  { id: 'logic',     name: 'Logic Inspector', sub: 'Auth & roles'      },
  { id: 'score',     name: 'Risk Scorer',     sub: 'Dedup & rank'      },
  { id: 'ai',        name: 'AI Remediation',  sub: 'Fix hints'         },
];

var NET_PIPE = [
  { id: 'dns',        name: 'DNS Resolver',    sub: 'A / AAAA / MX'    },
  { id: 'headers',    name: 'Header Inspect',  sub: 'Security headers' },
  { id: 'ssl',        name: 'SSL/TLS Audit',   sub: 'Cert & ciphers'   },
  { id: 'ports',      name: 'Port Probe',      sub: 'Common services'  },
  { id: 'whois',      name: 'WHOIS Lookup',    sub: 'Registrar info'   },
  { id: 'subdomains', name: 'Subdomain Enum',  sub: 'Common prefixes'  },
  { id: 'tech',       name: 'Tech Stack',      sub: 'CMS & frameworks' },
  { id: 'files',      name: 'Sensitive Files', sub: 'robots / sitemap' },
];

/* ─── PIPELINE RENDERER ─── */

function renderPipe(activeId, done, pipeType) {
  done = done || [];
  var pipeData = pipeType === 'net' ? NET_PIPE : PIPE;
  var el = document.getElementById('pipeList');
  if (!el) return;

  var html = '';
  pipeData.forEach(function(step) {
    var isDone = done.indexOf(step.id) > -1;
    var isAct  = step.id === activeId;
    var cls    = isDone ? 'done' : isAct ? 'active' : '';
    var dot    = isDone ? '&#10003;' : step.id.slice(0, 2).toUpperCase();

    html += '<div class="pipe-step ' + cls + '">';
    html += '<div class="pdot">' + dot + '</div>';
    html += '<div class="pinfo">';
    html += '<div class="pname">' + escHtml(step.name) + '</div>';
    html += '<div class="psub">'  + escHtml(step.sub)  + '</div>';
    html += '</div></div>';
  });

  el.innerHTML = html;
}

/* ─── PROGRESS & STATUS ─── */

function setProgress(pct, label) {
  var fill = document.getElementById('progFill');
  var lbl  = document.getElementById('progLabel');
  if (fill) fill.style.width = pct + '%';
  if (lbl)  lbl.textContent  = label || '';
}

function setStatus(mode, text) {
  var el = document.getElementById('scanStatus');
  if (!el) return;
  el.className = 'scan-status ' + (mode === 'ready' ? '' : mode);
  el.textContent = text || (mode === 'scanning' ? 'Scanning...' : mode === 'done' ? 'Done' : 'Ready');
}

/* ─── METRICS ─── */

function updateMetrics(findings) {
  findings = findings || [];
  var crit = findings.filter(function(f) { return f.sev === 'critical'; }).length;
  var high = findings.filter(function(f) { return f.sev === 'high'; }).length;
  var mods = (new Set(findings.map(function(f) { return f.type; }))).size;

  function set(id, val) { var e = document.getElementById(id); if (e) e.textContent = (val !== undefined ? val : '--'); }
  set('mTotal', findings.length);
  set('mCrit',  crit);
  set('mHigh',  high);
  set('mMods',  mods);
}

/* ─── RISK SCORE BAR ─── */

function showRiskScore(findings) {
  var wrap = document.getElementById('riskWrap');
  var fill = document.getElementById('riskFill');
  var val  = document.getElementById('riskVal');

  if (!findings || !findings.length) {
    if (wrap) wrap.style.display = 'none';
    return;
  }

  var score = computeRiskScore(findings);
  var color = riskColor(score);

  if (fill) { fill.style.width = score + '%'; fill.style.background = color; }
  if (val)  { val.textContent = score + ' / 100'; val.style.color = color; }
  if (wrap) wrap.style.display = 'block';
}

/* ─── LOG TERMINAL ─── */

function logEvent(state, msg, type) {
  type = type || 'info';
  var scrl = document.getElementById('logScrl');
  if (!scrl) return;

  var ts   = new Date().toTimeString().slice(0, 8);
  var tags = { info: '[INFO]', warn: '[WARN]', crit: '[CRIT]', ok: '[ OK ]' };
  var cls  = { info: 'linfo', warn: 'lwarn',  crit: 'lcrit',  ok: 'lok'   };

  var d = document.createElement('div');
  d.className = 'lline ' + (cls[type] || 'linfo');
  d.innerHTML =
    '<span class="lts">'  + ts + '</span>' +
    '<span class="ltag">' + (tags[type] || '[INFO]') + '</span>' +
    '<span class="lmsg">' + escHtml(msg) + '</span>';

  scrl.appendChild(d);
  scrl.scrollTop = scrl.scrollHeight;

  state.logCount = (state.logCount || 0) + 1;
  var cntEl = document.getElementById('logCount');
  if (cntEl) cntEl.textContent = state.logCount + ' events';
}

function clearLog(state) {
  var scrl = document.getElementById('logScrl');
  if (scrl) scrl.innerHTML = '';
  state.logCount = 0;
  var cntEl = document.getElementById('logCount');
  if (cntEl) cntEl.textContent = '0 events';
}

/* ─── SEVERITY PILLS ─── */

function buildSevPills(state, cfg) {
  var container = document.getElementById('sevPills');
  if (!container) return;

  var counts = {};
  (state.allFindings || []).forEach(function(f) {
    counts[f.sev] = (counts[f.sev] || 0) + 1;
  });

  /* Use SP_SEV_COLORS from utils.js — single source of truth */
  var html = '';
  ['critical','high','medium','low','info'].forEach(function(sev) {
    if (!counts[sev]) return;
    var c = SP_SEV_COLORS[sev] || { fg:'#6878a8', bg:'rgba(120,120,120,.1)', bd:'rgba(120,120,120,.25)' };
    html += '<div class="sev-pill" style="color:' + c.fg + ';background:' + c.bg + ';border-color:' + c.bd + '" ' +
            'onclick="filterBySev(\'' + sev + '\')" data-sev="' + sev + '">' +
            sev.toUpperCase() + ' <strong>' + counts[sev] + '</strong></div>';
  });

  container.innerHTML = html;
}

function clearSevPills() {
  var c = document.getElementById('sevPills');
  if (c) c.innerHTML = '';
}

/* ─────────────────────────────────────────
   MAIN AUDIT FUNCTION
   FIXED:
   - Now calls addHistoryEntry() so source scans populate history & dashboard
   - updateDashboard() called after scan
   - Sidebar badge updated after scan
───────────────────────────────────────── */

function runAudit(state, cfg) {
  state = state || APP.state;
  cfg   = cfg   || APP.cfg;

  var codeEl = document.getElementById('codeInput');
  var code   = codeEl ? codeEl.value : '';
  if (!code.trim()) {
    showToast('No code to scan. Paste code or drop a file first.', 'error');
    return;
  }

  /* Reset */
  state.allFindings = [];
  clearLog(state);
  clearSevPills();
  setStatus('scanning', 'Scanning...');
  renderPipe('parse', [], 'src');
  setProgress(0, 'Starting scan...');

  var steps    = ['parse','vendor','secrets','endpoints','xss','proto','crypto','supply','logic','score','ai'];
  var completed = [];
  var stepIdx   = 0;

  function nextStep() {
    if (stepIdx >= steps.length) {
      /* ── Run all detectors ── */
      var findings = [];
      if (cfg.modules.secrets)   findings = findings.concat(detectSecrets(code));
      if (cfg.modules.secrets)   findings = findings.concat(detectCredentials(code));
      if (cfg.modules.endpoints) findings = findings.concat(detectEndpoints(code));
      if (cfg.modules.xss)       findings = findings.concat(detectXSS(code));
      if (cfg.modules.proto)     findings = findings.concat(detectProto(code));
      if (cfg.modules.crypto)    findings = findings.concat(detectCrypto(code));
      if (cfg.modules.supply)    findings = findings.concat(detectSupply(code));
      if (cfg.modules.logic)     findings = findings.concat(detectLogic(code));
      if (cfg.modules.config)    findings = findings.concat(detectConfig(code));
      if (cfg.modules.inject !== false) findings = findings.concat(detectInjection(code));
      if (cfg.modules.storage !== false) findings = findings.concat(detectInsecureStorage(code));
      if (cfg.modules.duplicates !== false) findings = findings.concat(detectDuplicates(code));
      /* Python-specific detectors — run on all code (language-gated internally) */
      findings = findings.concat(detectDeserialization(code));
      findings = findings.concat(detectPathTraversal(code));
      findings = findings.concat(detectSSRF(code));

      /* Sort and store */
      /* Deduplicate — same rule on same line counts once */
      var seen = {};
      findings = findings.filter(function(f) {
        var key = f.id + ':' + f.line;
        if (seen[key]) return false;
        seen[key] = true;
        return true;
      });

      findings = sortBySeverity(findings);
      state.allFindings = findings;
      state.scanCount++;

      renderPipe(null, steps, 'src');
      setStatus('done', 'Done');
      setProgress(100, 'Scan complete');
      updateMetrics(findings);
      showRiskScore(findings);
      renderFindings(state, cfg);
      buildSevPills(state, cfg);
      updateDiffBanner();

      /* Update findings sidebar badge */
      var badge = document.getElementById('sbFindBadge');
      if (badge) {
        badge.textContent = findings.length;
        badge.style.display = findings.length ? 'inline-flex' : 'none';
      }

      logEvent(state, 'Scan completed — ' + findings.length + ' findings across ' + (new Set(findings.map(function(f){return f.type;}))).size + ' categories.', 'ok');

      /* ── FIXED: record history entry for source scans ── */
      var score = computeRiskScore(findings);
      addHistoryEntry({
        target:   'Source Code',
        type:     'SOURCE',
        findings: findings.length,
        critical: findings.filter(function(f){ return f.sev === 'critical'; }).length,
        high:     findings.filter(function(f){ return f.sev === 'high'; }).length,
        risk:     score,
        date:     new Date().toLocaleDateString(),
        time:     new Date().toLocaleTimeString(),
      });

      renderHistoryTable();
      updateDashboard(state);

      if (cfg.sound) playBeep();
      if (cfg.toasts) showToast(findings.length + ' findings detected. Risk score: ' + score + '/100.', findings.length ? 'warn' : 'success');
      return;
    }

    completed.push(steps[stepIdx]);
    renderPipe(steps[stepIdx], completed, 'src');
    setProgress(Math.round((stepIdx / steps.length) * 100), 'Analyzing: ' + steps[stepIdx]);
    logEvent(state, 'Running: ' + steps[stepIdx] + '...', 'info');
    stepIdx++;
    setTimeout(nextStep, 90);
  }

  nextStep();
}

/* ─── BASELINE MANAGEMENT ─── */

function saveBaseline() {
  try {
    var baseline = {
      findings: APP.state.allFindings || [],
      timestamp: new Date().toISOString(),
      count: (APP.state.allFindings || []).length,
    };
    localStorage.setItem('sp_baseline', JSON.stringify(baseline));
  } catch (e) {
    console.error('Failed to save baseline:', e);
  }
}

function loadBaseline() {
  try {
    var raw = localStorage.getItem('sp_baseline');
    if (raw) {
      APP.state.baseline = JSON.parse(raw);
      return APP.state.baseline;
    }
  } catch (e) {
    console.error('Failed to load baseline:', e);
  }
  return null;
}

function setBaseline() {
  if (!APP.state.allFindings || APP.state.allFindings.length === 0) {
    showToast('No findings to set as baseline. Run a scan first.', 'error');
    return;
  }

  saveBaseline();
  showToast('Baseline set with ' + APP.state.allFindings.length + ' findings.', 'success');
  updateDiffBanner();
}

function updateDiffBanner() {
  var banner = document.getElementById('diffBanner');
  if (!banner || !APP.state.baseline) return;

  var baselineCount = (APP.state.baseline.findings || []).length;
  var currentCount = (APP.state.allFindings || []).length;
  var diff = currentCount - baselineCount;

  /* Classes diff-banner--up / diff-banner--down / diff-banner--same are defined in style.css */
  banner.className = 'diff-banner ' + (diff > 0 ? 'diff-banner--up' : diff < 0 ? 'diff-banner--down' : 'diff-banner--same');
  if (diff > 0) {
    banner.innerHTML = '<span>+' + diff + ' findings</span> vs baseline';
  } else if (diff < 0) {
    banner.innerHTML = '<span>−' + Math.abs(diff) + ' findings</span> vs baseline';
  } else {
    banner.innerHTML = '<span>No change</span> from baseline';
  }
  banner.style.display = 'block';
}