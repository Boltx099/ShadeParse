/**
 * ShadeParse — ui.js
 * View switching, findings render, dashboard, toasts, theme.
 * FIXED:
 *  - toggleTheme() now swaps sun/moon icon correctly
 *  - loadTheme() applied before body render (called in <head> inline script)
 *  - filterBySev() actually filters findings, not just dims pills
 *  - updateDashboard() guard against missing elements
 */

'use strict';

/* ─── VIEW SWITCHING ─── */

var VIEW_NAMES = {
  scanner:   'Scanner',
  network:   'Network Recon',
  dashboard: 'Dashboard',
  findings:  'Findings',
  export:    'Export',
  history:   'History',
  settings:  'Settings',
};

function switchView(name) {
  document.querySelectorAll('.view').forEach(function(v) {
    v.classList.remove('active');
  });

  var target = document.getElementById('view-' + name);
  if (target) target.classList.add('active');

  var tbPage = document.getElementById('tbPage');
  if (tbPage) tbPage.textContent = VIEW_NAMES[name] || name;

  document.querySelectorAll('.sb-item').forEach(function(item) {
    item.classList.toggle('active', item.dataset.view === name);
  });

  /* Refresh relevant views when navigated to */
  if (name === 'dashboard')  updateDashboard(APP.state);
  if (name === 'history')    renderHistoryTable();
  if (name === 'findings')   renderFindingsView(APP.state);
  if (name === 'export')     buildSarif();

  if (window.innerWidth < 800) {
    var sb = document.getElementById('sidebar');
    if (sb) sb.classList.remove('open');
  }
}

function toggleSidebar() {
  var sb = document.getElementById('sidebar');
  if (sb) sb.classList.toggle('open');
}

/* ─── SCAN MODE SWITCHING ─── */

/* Per-mode snapshot/restore so each tab (source / domain / ip) keeps its
   own results. Without this, a code-audit finding bleeds into the IP-scan
   tab and an IP-scan card stays visible after switching back to source. */
function saveModeSnapshot(mode) {
  if (!mode || !APP.state.modeResults) return;
  var netEl  = document.getElementById('networkResults');
  var diffEl = document.getElementById('diffCodeWrap');
  var codeEl = document.getElementById('codeInput');
  APP.state.modeResults[mode] = {
    findings:    (APP.state.allFindings || []).slice(),
    networkHtml: netEl  ? netEl.innerHTML  : '',
    diffHtml:    diffEl ? diffEl.innerHTML : '',
    codeText:    (mode === 'source' && codeEl) ? codeEl.value : '',
    when:        Date.now(),
  };
}

function loadModeSnapshot(mode) {
  var snap = APP.state.modeResults && APP.state.modeResults[mode];
  var findings = (snap && snap.findings) ? snap.findings.slice() : [];
  APP.state.allFindings = findings;

  var netEl  = document.getElementById('networkResults');
  if (netEl) netEl.innerHTML = (snap && snap.networkHtml) || '';

  var diffEl = document.getElementById('diffCodeWrap');
  if (diffEl) diffEl.innerHTML = (snap && snap.diffHtml) || '';

  /* Restore the code textarea for source mode so the user can see what
     was audited (or get back to an empty textarea on a fresh tab). */
  if (mode === 'source') {
    var codeEl = document.getElementById('codeInput');
    if (codeEl) codeEl.value = (snap && snap.codeText) || '';
  }

  /* Re-render the dependents from the restored findings array */
  if (typeof updateMetrics  === 'function') updateMetrics(findings);
  if (typeof showRiskScore  === 'function') showRiskScore(findings);
  if (typeof renderFindings === 'function') renderFindings(APP.state, APP.cfg);
  if (typeof buildSevPills  === 'function') buildSevPills(APP.state, APP.cfg);
  if (typeof buildSarif     === 'function') buildSarif();

  var badge = document.getElementById('sbFindBadge');
  if (badge) {
    badge.textContent = findings.length;
    badge.style.display = findings.length ? 'inline-flex' : 'none';
  }
}

function setScanMode(mode) {
  /* Snapshot the OUTGOING mode before swapping panels */
  if (APP.state.currentMode && APP.state.currentMode !== mode) {
    saveModeSnapshot(APP.state.currentMode);
  }

  APP.state.currentMode = mode;

  var panels = { source: 'sourcePanel', domain: 'domainPanel', ip: 'ipPanel' };
  Object.keys(panels).forEach(function(key) {
    var el = document.getElementById(panels[key]);
    if (el) el.style.display = (key === mode) ? 'block' : 'none';
  });

  document.querySelectorAll('.smt').forEach(function(btn) {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  });

  /* Switch pipeline to net or source */
  renderPipe(null, [], mode === 'source' ? 'src' : 'net');

  /* Restore the INCOMING mode's previously saved results (or clear if none) */
  loadModeSnapshot(mode);
}

function runCurrentScan() {
  var mode = APP.state.currentMode;
  if (mode === 'source')      runAudit(APP.state, APP.cfg);
  else if (mode === 'domain') runNetworkScan();
  else if (mode === 'ip')     runIpScan();
}

/* ─── FINDINGS RENDER ─── */

function renderFindings(state, cfg) {
  var container = document.getElementById('findingsArea');
  if (!container) return;

  if (!state.allFindings || !state.allFindings.length) {
    container.innerHTML = '<div class="findings-placeholder">Run a scan to see findings here.</div>';
  } else {
    container.innerHTML = buildFindingsHtml(state.allFindings);
  }

  renderFindingsView(state);
}

function renderFindingsView(state) {
  var wrap = document.getElementById('findingsListWrap');
  if (!wrap) return;

  var countEl = document.getElementById('findingsCount');

  if (!state.allFindings || !state.allFindings.length) {
    wrap.innerHTML = '<div class="nr-placeholder">Run a scan to see findings here.</div>';
    if (countEl) countEl.textContent = '0 findings';
    return;
  }

  wrap.innerHTML = buildFindingsHtml(state.allFindings);
  if (countEl) countEl.textContent = state.allFindings.length + ' findings';
}

function filterFindings() {
  var sevEl    = document.getElementById('findingsFilter');
  var typeEl   = document.getElementById('findingsTypeFilter');
  var searchEl = document.getElementById('findingsSearch');

  var sev    = sevEl    ? sevEl.value    : 'all';
  var type   = typeEl   ? typeEl.value   : 'all';
  var search = searchEl ? (searchEl.value || '').toLowerCase() : '';

  var filtered = (APP.state.allFindings || []).filter(function(f) {
    if (sev  !== 'all' && f.sev  !== sev)  return false;
    if (type !== 'all' && f.type !== type) return false;
    if (search) {
      var haystack = (f.title + ' ' + f.desc + ' ' + (f.match || '')).toLowerCase();
      if (haystack.indexOf(search) === -1) return false;
    }
    return true;
  });

  var wrap = document.getElementById('findingsListWrap');
  if (!wrap) return;
  wrap.innerHTML = filtered.length
    ? buildFindingsHtml(filtered)
    : '<div class="nr-placeholder">No findings match the filter.</div>';

  var countEl = document.getElementById('findingsCount');
  if (countEl) countEl.textContent = filtered.length + ' findings';
}

/* FIXED: filterBySev now actually filters findings list, not just visual dim */
function filterBySev(sev) {
  /* Toggle pill active state */
  var pills = document.querySelectorAll('.sev-pill');
  var alreadyActive = false;
  pills.forEach(function(p) {
    if (p.dataset.sev === sev && p.classList.contains('active-pill')) alreadyActive = true;
  });

  pills.forEach(function(p) {
    p.classList.remove('active-pill', 'dimmed');
    if (!alreadyActive) {
      if (p.dataset.sev === sev) p.classList.add('active-pill');
      else p.classList.add('dimmed');
    }
  });

  var wrap = document.getElementById('findingsListWrap');
  if (!wrap) return;

  if (alreadyActive) {
    /* Reset to show all */
    wrap.innerHTML = buildFindingsHtml(APP.state.allFindings || []);
    return;
  }

  var filtered = (APP.state.allFindings || []).filter(function(f) { return f.sev === sev; });
  wrap.innerHTML = filtered.length
    ? buildFindingsHtml(filtered)
    : '<div class="nr-placeholder">No ' + sev + ' findings.</div>';

  var countEl = document.getElementById('findingsCount');
  if (countEl) countEl.textContent = filtered.length + ' findings';
}

function buildFindingsHtml(findings) {
  if (!findings || !findings.length) return '<div class="nr-placeholder">No findings.</div>';
  var html = '';
  findings.forEach(function(f, i) {
    var sc  = sevColor(f.sev);
    var bg  = typeBg(f.type);
    var fg  = typeColor(f.type);
    /* Use stable ID derived from finding's own id + index so filter never breaks */
    var uid = 'fc-' + (f.id ? f.id.replace(/[^a-zA-Z0-9_-]/g, '_') : i) + '-' + i;

    html += '<div class="finding-card" id="' + uid + '" data-uid="' + uid + '">';
    html += '<div class="fc-head" onclick="toggleFinding(this)">';
    html += '<div class="fc-sev-dot" style="background:' + sc + '"></div>';
    html += '<div class="fc-type-badge" style="background:' + bg + ';color:' + fg + '">' + escHtml(f.type) + '</div>';
    html += '<div class="fc-title">' + escHtml(f.title) + '</div>';
    if (f.isNew) html += '<span class="fc-new-badge">NEW</span>';
    html += '<div class="fc-loc">' + escHtml(f.loc) + '</div>';
    html += '<div class="fc-confidence">' + (f.confidence || 0) + '%</div>';
    html += '<svg class="fc-chevron" viewBox="0 0 20 20"><path d="M5 8l5 5 5-5" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    html += '</div>';
    html += '<div class="fc-body">';
    html += '<div class="fc-desc">' + escHtml(f.desc) + '</div>';
    if (f.snippet) {
      html += '<div class="fc-snippet">' + escHl(f.snippet, f.match) + '</div>';
    }
    if (f.taint) {
      html += '<div class="fc-taint">';
      html += '<span class="taint-src">SRC: ' + escHtml(f.taint.source) + '</span>';
      if (f.taint.flow && f.taint.flow.length) {
        html += '<span class="taint-arrow">&#8594;</span>';
        html += '<span class="taint-flow">' + f.taint.flow.map(escHtml).join(' &#8594; ') + '</span>';
      }
      html += '<span class="taint-arrow">&#8594;</span>';
      html += '<span class="taint-sink">SINK: ' + escHtml(f.taint.sink) + '</span>';
      html += '</div>';
    }
    if (f.remediation) {
      html += '<div class="fc-remediation">';
      html += '<div class="fc-rem-label">REMEDIATION</div>';
      html += '<div class="fc-rem-text">' + escHtml(f.remediation.text) + '</div>';
      if (f.remediation.fix) {
        html += '<div class="fc-rem-fix">' + escHtml(f.remediation.fix) + '</div>';
      }
      html += '</div>';
    }
    html += '</div></div>';
  });
  return html;
}

/* FIXED: Accept the clicked fc-head element and walk up to the card.
   Previously used array index which broke after filtering. */
function toggleFinding(headEl) {
  var card = headEl.closest ? headEl.closest('.finding-card') : headEl.parentElement;
  if (card) card.classList.toggle('expanded');
}

/* ─── DASHBOARD ─── */

function updateDashboard(state) {
  if (!state) return;
  var findings = state.allFindings || [];
  var crit  = findings.filter(function(f) { return f.sev === 'critical'; }).length;
  var high  = findings.filter(function(f) { return f.sev === 'high'; }).length;
  var score = computeRiskScore(findings);

  animateCounter('dashCrit',  crit);
  animateCounter('dashHigh',  high);
  animateCounter('dashTotal', findings.length);
  animateCounter('dashScans', state.scanHistory ? state.scanHistory.length : 0);

  /* Threat level */
  var wtl   = document.getElementById('wtlValue');
  var fill  = document.getElementById('wtlFill');
  var color, label;

  if (!findings.length)  { label = 'UNKNOWN';  color = 'var(--text2)'; }
  else if (score >= 70)  { label = 'CRITICAL';  color = 'var(--red)';   }
  else if (score >= 40)  { label = 'HIGH';      color = 'var(--coral)'; }
  else if (score >= 20)  { label = 'MEDIUM';    color = 'var(--amber)'; }
  else                   { label = 'LOW';       color = 'var(--green)'; }

  if (wtl)  { wtl.textContent = label; wtl.style.color = color; }
  if (fill) { fill.style.width = score + '%'; fill.style.background = color; }

  /* Risk arc gauge */
  var arc = document.getElementById('dashRiskArc');
  var val = document.getElementById('dashRiskVal');
  if (arc && findings.length) {
    var offset = 157 - (score / 100 * 157);
    arc.style.strokeDashoffset = offset;
    arc.style.stroke = score >= 70 ? 'var(--red)' : score >= 40 ? 'var(--amber)' : 'var(--green)';
  }
  if (val) val.textContent = findings.length ? score : '--';

  renderRecentTargets(state);
}

function animateCounter(id, target) {
  var el = document.getElementById(id);
  if (!el) return;
  var start = parseInt(el.textContent, 10) || 0;
  var diff  = target - start;
  var steps = 20;
  var i     = 0;
  function tick() {
    i++;
    el.textContent = Math.round(start + (diff * i / steps));
    if (i < steps) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function renderRecentTargets(state) {
  var container = document.getElementById('dashTargets');
  if (!container) return;

  var history = state.scanHistory || [];
  if (!history.length) {
    container.innerHTML = '<div class="empty-state">No scans run yet.</div>';
    return;
  }

  var recent = history.slice(-5).reverse();
  container.innerHTML = recent.map(function(h) {
    var rc = h.risk >= 70 ? 'var(--red)' : h.risk >= 40 ? 'var(--amber)' : 'var(--green)';
    return '<div class="target-item">' +
           '<div class="ti-dot" style="background:' + rc + '"></div>' +
           '<div class="ti-name">' + escHtml(h.target) + '</div>' +
           '<div class="ti-badge" style="background:rgba(79,143,255,.1);color:var(--accent)">' + escHtml(h.type) + '</div>' +
           '<div class="ti-badge" style="background:rgba(255,77,106,.1);color:var(--red)">' + h.findings + ' findings</div>' +
           '</div>';
  }).join('');
}

/* ─── HISTORY TABLE ─── */

function renderHistoryTable() {
  var history = APP.state.scanHistory || [];
  var details = APP.state.scanHistoryDetail || {};

  ['dashHistoryBody', 'historyBody'].forEach(function(id) {
    var tbody = document.getElementById(id);
    if (!tbody) return;

    if (!history.length) {
      var cols = (id === 'historyBody') ? 8 : 5;
      tbody.innerHTML = '<tr><td colspan="' + cols + '" class="empty-cell">No scan history yet.</td></tr>';
      return;
    }

    var rows = history.slice(-20).reverse().map(function(h) {
      var rc = h.risk >= 70 ? 'var(--red)' : h.risk >= 40 ? 'var(--amber)' : 'var(--green)';
      var hasDetail = !!(h.id && details[h.id]);

      /* SOURCE rows store target as pre-built HTML (with the language
         badge); other types are plain text and need escaping. */
      var targetCell = (h.type === 'SOURCE')
        ? (h.target || '')
        : escHtml(h.target || '');

      /* Tooltip — show a code preview for source scans so the user can
         remember what they audited at a glance. */
      var baseTitle = h.type === 'SOURCE' && h.preview
        ? (h.langLabel || 'Code') + ' · ' + (h.lineCount || 0) + ' lines\n\n' + h.preview
        : '';
      var detailTitle = hasDetail
        ? 'Click to restore this scan&#39;s results'
        : 'Detail not in memory (session ended). Re-run scan to view results.';
      var titleAttr = baseTitle
        ? (escHtml(baseTitle) + '\n\n— ' + detailTitle)
        : detailTitle;

      var rowOpen;
      if (h.id) {
        var op = hasDetail ? '1' : '.55';
        rowOpen = '<tr data-hist-id="' + escHtml(h.id) + '" '+
                  'style="cursor:pointer;opacity:'+op+'" '+
                  'title="' + titleAttr + '" '+
                  'onclick="loadHistoryEntry(\'' + escHtml(h.id) + '\')">';
      } else {
        rowOpen = '<tr style="opacity:.6">';
      }

      if (id === 'historyBody') {
        return rowOpen +
          '<td>' + targetCell  + '</td>' +
          '<td>' + escHtml(h.type) + '</td>' +
          '<td>' + h.findings  + '</td>' +
          '<td style="color:var(--red)">'   + (h.critical || 0) + '</td>' +
          '<td style="color:var(--coral)">' + (h.high || 0)     + '</td>' +
          '<td style="color:' + rc + '">'  + h.risk + '/100' + '</td>' +
          '<td>' + (h.date || '')      + '</td>' +
          '<td>' + (h.time || '')      + '</td>' +
          '</tr>';
      } else {
        return rowOpen +
          '<td>' + targetCell  + '</td>' +
          '<td>' + escHtml(h.type) + '</td>' +
          '<td>' + h.findings  + '</td>' +
          '<td style="color:' + rc + '">'     + h.risk + '/100' + '</td>' +
          '<td>' + (h.time || '')             + '</td>' +
          '</tr>';
      }
    }).join('');

    tbody.innerHTML = rows;
  });

  var actEl = document.getElementById('historyActions');
  if (actEl) actEl.style.display = history.length ? 'block' : 'none';
}

/* Click a history row → restore that scan's findings + rendered cards
   into the appropriate scan-mode tab and switch to the scanner view. */
function loadHistoryEntry(id) {
  if (!id) return;
  var entry = (APP.state.scanHistory || []).filter(function(e){ return e.id === id; })[0];
  if (!entry) {
    if (typeof showToast === 'function') showToast('History entry not found.', 'warn');
    return;
  }
  var detail = APP.state.scanHistoryDetail && APP.state.scanHistoryDetail[id];
  if (!detail) {
    if (typeof showToast === 'function')
      showToast('That scan\'s detailed results were not kept in memory (session reset). Re-run the scan to view results again.', 'info');
    return;
  }

  var modeMap = { 'SOURCE':'source', 'DOMAIN':'domain', 'IP':'ip' };
  var mode = modeMap[entry.type] || 'source';

  /* Snapshot whatever's currently visible in the live mode, then
     overwrite the target mode's slot with the historic detail. */
  if (APP.state.currentMode && APP.state.currentMode !== mode) {
    saveModeSnapshot(APP.state.currentMode);
  }
  APP.state.modeResults[mode] = {
    findings:    (detail.findings || []).slice(),
    networkHtml: detail.networkHtml || '',
    diffHtml:    detail.diffHtml    || '',
    codeText:    detail.codeText    || '',
    when:        detail.when        || Date.now(),
  };

  setScanMode(mode);                 // swaps panels and calls loadModeSnapshot internally
  switchView('scanner');             // bring user to where the results render

  if (typeof showToast === 'function')
    showToast('Restored: ' + entry.target + ' — ' + (entry.date || '') + ' ' + (entry.time || ''), 'success');
}

/* ─── TOASTS ─── */

function showToast(msg, type) {
  /* Respect toasts setting */
  if (typeof APP !== 'undefined' && APP.cfg && !APP.cfg.toasts) return;
  type = type || 'info';

  var container = document.getElementById('toastContainer');
  if (!container) return;

  var toast = document.createElement('div');
  toast.className = 'toast ' + type;
  toast.innerHTML = '<div class="toast-dot"></div><span>' + escHtml(msg) + '</span>';
  container.appendChild(toast);

  setTimeout(function() {
    toast.classList.add('out');
    setTimeout(function() {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 3500);
}

/* ─── THEME TOGGLE ───
   FIXED: icon visibility now driven by data-theme attribute via CSS,
          and toggleTheme() explicitly updates icon classes too.
───────────────────────────────────────── */

function toggleTheme() {
  var html    = document.documentElement;
  var current = html.getAttribute('data-theme') || 'light';
  var next    = (current === 'dark') ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('sp_theme', next);
  _applyThemeIcon(next);
  /* Update tooltip */
  var btn = document.getElementById('themeToggle');
  if (btn) btn.title = next === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
}

function loadTheme() {
  var saved = localStorage.getItem('sp_theme') || 'light';
  document.documentElement.setAttribute('data-theme', saved);
  /* Icon update is deferred — DOM not ready yet when this runs from <head> */
  document.addEventListener('DOMContentLoaded', function() { _applyThemeIcon(saved); });
}

function _applyThemeIcon(theme) {
  var iconDark  = document.querySelector('.theme-toggle .icon-dark');
  var iconLight = document.querySelector('.theme-toggle .icon-light');
  if (!iconDark || !iconLight) return;
  if (theme === 'dark') {
    iconDark.style.display  = 'block';
    iconLight.style.display = 'none';
  } else {
    iconDark.style.display  = 'none';
    iconLight.style.display = 'block';
  }
  var btn = document.getElementById('themeToggle');
  if (btn) btn.title = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
}

/* ─── LIVE CLOCK ─── */

function startClock() {
  function tick() {
    var el = document.getElementById('liveClock');
    if (el) el.textContent = new Date().toTimeString().slice(0, 8);
  }
  tick();
  setInterval(tick, 1000);
}

/* ─── GREETING ─── */

function setGreeting() {
  var h        = new Date().getHours();
  var greeting = h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';

  var el = document.getElementById('wcGreeting');
  if (el) el.textContent = greeting;

  var name = (typeof spGetUser === 'function') ? spGetUser() : 'Operator';
  var nameEl = document.getElementById('wcName');
  if (nameEl) nameEl.textContent = name;

  var sbUser = document.getElementById('sbUsername');
  if (sbUser) sbUser.textContent = name;

  var sbAvatar = document.getElementById('sbAvatar');
  if (sbAvatar) sbAvatar.textContent = (name[0] || 'O').toUpperCase();
}

/* ─── FILE DROP ZONE ─── */

function initDropZone() {
  var zone = document.getElementById('dropZone');
  var inp  = document.getElementById('fileInput');
  var code = document.getElementById('codeInput');
  if (!zone || !inp || !code) return;

  zone.addEventListener('dragover', function(e) {
    e.preventDefault();
    zone.classList.add('over');
  });

  zone.addEventListener('dragleave', function(e) {
    /* Only remove if leaving the zone entirely */
    if (!zone.contains(e.relatedTarget)) zone.classList.remove('over');
  });

  zone.addEventListener('drop', function(e) {
    e.preventDefault();
    zone.classList.remove('over');
    var file = e.dataTransfer.files[0];
    if (file) readFile(file, code);
  });

  /* Clicking the zone triggers file picker */
  zone.addEventListener('click', function(e) {
    if (e.target !== inp) inp.click();
  });

  inp.addEventListener('change', function() {
    if (inp.files[0]) readFile(inp.files[0], code);
  });
}

function readFile(file, target) {
  var maxSize = 5 * 1024 * 1024; /* 5 MB */
  if (file.size > maxSize) {
    showToast('File too large (max 5 MB).', 'error');
    return;
  }

  var reader = new FileReader();
  reader.onload = function(e) {
    target.value = e.target.result;
    showToast('Loaded: ' + file.name + ' (' + Math.round(file.size / 1024) + ' KB)', 'success');
    logEvent(APP.state, 'File loaded: ' + file.name + ' — ' + Math.round(file.size / 1024) + ' KB, ready to scan.', 'ok');
  };
  reader.onerror = function() {
    showToast('Failed to read file.', 'error');
  };
  reader.readAsText(file);
}

/* ─── KEYBOARD SHORTCUTS ─── */

function initShortcuts() {
  document.addEventListener('keydown', function(e) {
    /* Skip if typing in an input */
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (!e.ctrlKey && !e.metaKey) return;
    switch (e.key) {
      case 'Enter': e.preventDefault(); runCurrentScan();          break;
      case 'k':     e.preventDefault(); clearInput();              break;
      case '1':     e.preventDefault(); setScanMode('source');     break;
      case '2':     e.preventDefault(); setScanMode('domain');     break;
      case '3':     e.preventDefault(); setScanMode('ip');         break;
      case 'd':     e.preventDefault(); switchView('dashboard');   break;
      case 'e':     e.preventDefault(); switchView('export');      break;
    }
  });
}

/* ─── INPUT HELPERS ─── */

function clearInput() {
  var inp = document.getElementById('codeInput');
  if (inp) { inp.value = ''; showToast('Input cleared.', 'info'); }
}

function loadSample(type) {
  var code = document.getElementById('codeInput');
  if (!code || typeof SAMPLES === 'undefined') return;
  var sample = SAMPLES[type] || SAMPLES['mega'] || '';
  if (!sample) { showToast('Sample not found.', 'warn'); return; }
  code.value = sample;
  showToast('Sample loaded: ' + type, 'info');
  logEvent(APP.state, 'Sample code loaded: ' + type, 'info');
}

/* ─── SOUND ─── */

function playBeep() {
  try {
    var ctx  = new (window.AudioContext || window.webkitAudioContext)();
    var osc  = ctx.createOscillator();
    var gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    osc.frequency.setValueAtTime(440, ctx.currentTime + 0.1);
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.setValueAtTime(0, ctx.currentTime + 0.3);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.3);
  } catch (e) {}
}

/* ─── NETWORK RESULTS PLACEHOLDER ─── */

function showScanningPlaceholder() {
  var container = document.getElementById('findingsArea');
  if (container) container.innerHTML = '<div class="findings-placeholder">Scan in progress...</div>';
}

function setTarget(val) {
  var el = document.getElementById('targetInput');
  if (el) el.value = val;
}

function setIpTarget(val) {
  var el = document.getElementById('ipTargetInput');
  if (el) el.value = val;
}

/* ═══════════════════════════════════════
   DRAG-TO-RESIZE SPLITTERS
   ═══════════════════════════════════════ */

function initResizers() {
  _initSidebarResizer();
  _initScannerSplitter();
}

/* ── Sidebar resizer ── */
function _initSidebarResizer() {
  var resizer = document.getElementById('sidebarResizer');
  if (!resizer) return;

  var MIN_W = 160;
  var MAX_W = 400;

  function positionResizer(w) {
    resizer.style.left = (w - 3) + 'px';
  }

  function applyWidth(w) {
    w = Math.max(MIN_W, Math.min(MAX_W, w));
    document.documentElement.style.setProperty('--sidebar-w', w + 'px');
    document.querySelector('.sidebar').style.width = w + 'px';
    document.querySelector('.main-area').style.marginLeft = w + 'px';
    positionResizer(w);
    localStorage.setItem('sp_sidebar_w', w);
  }

  // Restore saved width
  var saved = parseInt(localStorage.getItem('sp_sidebar_w'));
  if (saved) applyWidth(saved);
  else positionResizer(parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sidebar-w')) || 220);

  /* Double-click resets sidebar to default width */
  resizer.addEventListener('dblclick', function() {
    applyWidth(220);
    localStorage.removeItem('sp_sidebar_w');
  });

  resizer.addEventListener('mousedown', function(e) {
    e.preventDefault();
    document.body.classList.add('sp-resizing');
    resizer.classList.add('dragging');

    function onMove(e) {
      applyWidth(e.clientX);
    }
    function onUp() {
      document.body.classList.remove('sp-resizing');
      resizer.classList.remove('dragging');
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
}

/* ── Scanner left/right splitter ── */
function _initScannerSplitter() {
  var splitter = document.getElementById('scannerSplitter');
  var leftPanel = document.getElementById('scannerLeft');
  var rightPanel = document.getElementById('scannerRight');
  var layout = document.getElementById('scannerLayout');
  if (!splitter || !leftPanel || !rightPanel || !layout) return;

  var MIN_LEFT = 280;
  var MIN_RIGHT = 220;

  // Restore saved split
  var savedLeft = localStorage.getItem('sp_scanner_left_w');
  if (savedLeft) {
    leftPanel.style.flex = 'none';
    leftPanel.style.width = savedLeft + 'px';
    rightPanel.style.flex = '1 1 auto';
  }

  /* Double-click resets scanner split to default */
  splitter.addEventListener('dblclick', function() {
    leftPanel.style.flex  = '1 1 auto';
    leftPanel.style.width = '';
    rightPanel.style.flex = '0 0 300px';
    localStorage.removeItem('sp_scanner_left_w');
  });

  splitter.addEventListener('mousedown', function(e) {
    e.preventDefault();
    document.body.classList.add('sp-resizing');
    splitter.classList.add('dragging');

    var startX = e.clientX;
    var startLeftW = leftPanel.getBoundingClientRect().width;

    function onMove(e) {
      var delta = e.clientX - startX;
      var newLeft = startLeftW + delta;
      var totalW = layout.getBoundingClientRect().width - 6; // 6 = splitter width
      var newRight = totalW - newLeft;

      if (newLeft < MIN_LEFT || newRight < MIN_RIGHT) return;

      leftPanel.style.flex = 'none';
      leftPanel.style.width = newLeft + 'px';
      rightPanel.style.flex = '1 1 auto';
      rightPanel.style.minWidth = MIN_RIGHT + 'px';
      localStorage.setItem('sp_scanner_left_w', newLeft);
    }

    function onUp() {
      document.body.classList.remove('sp-resizing');
      splitter.classList.remove('dragging');
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }

    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
}
