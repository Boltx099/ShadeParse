# SIEM Module — Engineering Spec & Roadmap

Treat this file as the canonical implementation contract for SIEM features.
Every section below is precise enough to be opened standalone and turned
into code without re-reading the existing siem.js. Cross-references use
file paths and IDs from the actual codebase.

---

## 0 · Codebase ground truth (do not duplicate)

### 0.1 File layout

```
ShadeParse/
├── index.html                     view-siem section starts L600
├── css/style.css                  all .siem-* classes live here
├── js/
│   ├── siem.js                    1955 lines, this module's brain
│   ├── network.js                 reusable: ipGeo, urlHausLookup,
│   │                              threatFoxLookup, classifyTarget
│   ├── ui.js                      switchView, escHtml, showToast
│   ├── state.js                   APP.state, scanHistory, modeResults
│   ├── export.js                  buildSarif (extend for SIEM export)
│   └── utils.js                   shared helpers
└── SIEM_ROADMAP.md                this file
```

### 0.2 Authoritative data shapes

```ts
// One alert as produced by siemClientSideAnalyze and consumed everywhere
type Alert = {
  type:              string;     // "SQL Injection" | "Cross-Site Scripting (XSS)" | …
  severity:          'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  ip:                string | null;
  timestamp:         string | null;   // ISO-8601 prefix, may be partial
  endpoint:          string | null;   // request path
  evidence:          string;          // first 200 chars of source line
  risk_score:        number;          // 0–100
  occurrences?:      number;          // dedupe count (set during aggregation)
  patterns?:         string[];        // matched regex names
  correlation_note?: string;          // human note from correlation pass

  // ── new fields that roadmap items add ──
  mitre?:        { id: string; name: string; tactic: string };  // §2.1
  tags?:         string[];      // 'tor', 'aws', 'cdn', 'beacon-candidate', …
  geo?:          { country: string; cc: string; city?: string };
  asn?:          { asn: string; org: string };
  dismissed?:    boolean;       // §4.3
  dismissReason?:string;
  isNew?:        boolean;       // §4.4 baseline diff
  customRuleId?: string;        // §5.1
  sigmaRuleId?:  string;        // §5.2
  bucketIdx?:    number;        // §1.1 histogram bucket index, set by renderer
};

// Severity → presentation map (siem.js L36)
SEV_CONFIG['CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'] = {
  color: 'var(--red|coral|amber|green|teal)',
  icon:  string,
  order: 0..4
};

// KQL token shape (siem.js L1029, used by both alert and log search)
type Token = {
  field:  string;             // 'severity'|'ip'|'method'|'path'|'status'|…|'any'
  op:     ':' | '~' | '>' | '>=' | '<' | '<=' | '!=' | '=';
  val:    string | number | RegExp;
  kind:   'str' | 'num' | 'glob' | 'regex';
  negate: boolean;
  raw:    string;
  highlightRe?: RegExp;        // for glob/regex; unanchored, /gi
};
```

### 0.3 Event/state singletons in siem.js

| Singleton           | Line  | Purpose                                          |
|---------------------|-------|--------------------------------------------------|
| `SIEM`              | 27    | core state: `lastResult`, `lastRequest`, etc.    |
| `SEV_CONFIG`        | 36    | severity→presentation map                        |
| `SIEM_PIPE`         | 16    | pipeline step list for `siemPipeList`            |
| `_CLIENT_SQLI`      | 224   | SQLi regex array                                 |
| `_CLIENT_XSS`       | 228   | XSS regex array                                  |
| `_CLIENT_BRUTE`     | 232   | sensitive-path regex                             |
| `_CLIENT_SCAN`      | 233   | scanner UA regex                                 |
| `SIEM_SAMPLE_LOGS`  | 575   | demo data                                        |
| `SIEM_SEARCH`       | 607   | alert KQL state: `tokens[]`, `quickFilters[]`    |
| `_LOG_SEARCH`       | 962   | raw-log search state: `tokens[]`, `matches[]`,…  |
| `_LIVE`             | 1487  | live monitor state                               |
| `_FWD`              | 1761  | log-forwarding state                             |

### 0.4 Key DOM IDs in `view-siem` (index.html L600+)

```
siemLogSearchInput        raw-log KQL search input (top of view)
siemLogSearchCount        match count badge
siemLogSearchBar          wrapper div (positioning anchor)
siemLogMatchViewer        legacy popup viewer
siemLogPaste              raw log textarea
siemLogFilterPanel        Splunk-style filtered events panel (created by JS)
siemPipeList              pipeline steps
siemSevCounters           severity card row
siemAlertsBody            alerts <tbody>
siemAlertsEmpty           empty-state message
siemSearchInput           alert KQL search input
siemFilterChips           active-token chips
siemQuickFilters          quick-filter buttons row
siemAuditLog              right-side audit log feed
```

### 0.5 Existing entry points safe to call from new code

```
// siem.js
siemAddLog(msg, type)                 audit-log append (info|warn|error|ok)
siemHandleResult(data)                main render entry, takes Result obj
siemRenderAlertsTable(alerts)         (overridden L921 to seed cache too)
siemRefreshAlertsView()               re-render after token/quick-filter change
siemApplySearch()                     re-parse alert KQL + refresh
SIEM_SEARCH.tokens.push(...)          add a parsed token
SIEM_SEARCH.quickFilters.push(...)    add a quick-filter

// network.js
ipGeo(ip)                             merged-source geolocation
internetDbLookup(ip)                  Shodan ports + CVEs
urlHausLookup(host)                   abuse.ch URLhaus
threatFoxLookup(target)               abuse.ch ThreatFox IOC
classifyTarget(target, R)             cloud/CDN/anycast classifier

// ui.js / utils.js
escHtml(str)                          REQUIRED for any HTML interpolation
showToast(msg, type)                  toast notifications
```

### 0.6 Persistence keys

| Key                          | Spec section | Type      | Schema                                      |
|------------------------------|--------------|-----------|---------------------------------------------|
| `sp_siem_saved_searches`     | §4.1         | array     | `[{name, query, when}]`                     |
| `sp_siem_dismissed`          | §4.3         | object    | `{ <signature>: { reason, when } }`         |
| `sp_siem_baseline`           | §4.4         | object    | `{ when, signatures: string[] }`            |
| `sp_siem_custom_rules`       | §5.1         | array     | `[{id, name, regex, severity, mitre, desc}]`|
| `sp_siem_sigma_rules`        | §5.2         | array     | `[{id, sigmaRaw, parsed, enabled}]`         |
| `sp_siem_threatintel_cache`  | §3.1         | object    | `{ <ip>: { online, when, source } }`        |
| `sp_siem_tor_exits`          | §3.2         | object    | `{ when, set: string[] }` (1h TTL)          |

### 0.7 Helpers to add once, used by many features

```js
// All-purpose alert signature for dedup / dismissal / baseline diff.
function siemAlertSignature(alert) {
  return [alert.type, alert.severity, alert.ip||'-',
          alert.endpoint||'-', alert.timestamp||'-'].join('|');
}

// Append a KQL token to siemSearchInput and re-apply.
// Used by §1.2 widgets and §4.2 click-to-filter.
function siemAppendKqlToken(field, value) {
  var input = document.getElementById('siemSearchInput');
  if (!input) return;
  var token = field === 'any' ? value : (field + ':' + value);
  // Quote if contains whitespace
  if (/\s/.test(token)) token = field + ':"' + value + '"';
  input.value = (input.value.trim() + ' ' + token).trim();
  siemApplySearch();
}

// Bucket alerts by time. Returns [{ start, end, count, sevCounts }].
function siemBucketByTime(alerts, startMs, endMs, bucketCount) { … }

// All distinct values of a field across alerts, with counts.
function siemTopN(alerts, fieldGetter, n) {
  var counts = {};
  alerts.forEach(a => {
    var v = fieldGetter(a); if (!v) return;
    counts[v] = (counts[v]||0) + 1;
  });
  return Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,n);
}
```

---

## 1 · Visualization & situational awareness

### 1.1 Time histogram

**User story:** Above the alerts table, a horizontal bar chart with one bar
per time bucket. Stacked by severity. Click a bar → time-range filter
narrows to that bucket. Hover → tooltip with exact counts.

**DOM placement:**
- Insert a new section between `siemSevCounters` (index.html L806) and the
  alerts-table section title (L809).
- `<div class="siem-section-title">EVENT TIMELINE</div>`
- `<div id="siemTimeline" class="siem-timeline"></div>`

**Bucketing algorithm:**
```js
// auto bucket size given range
function pickBucketMs(rangeMs) {
  // target ~50 buckets
  var target = rangeMs / 50;
  var candidates = [
    1_000, 5_000, 10_000, 30_000,
    60_000, 5*60_000, 10*60_000, 30*60_000,
    3_600_000, 6*3_600_000, 24*3_600_000,
    7*24*3_600_000
  ];
  for (var i=0;i<candidates.length;i++)
    if (candidates[i] >= target) return candidates[i];
  return candidates[candidates.length-1];
}
```

**Render pseudo:**
```js
function siemRenderTimelineHisto(alerts) {
  var times = alerts.map(a => Date.parse(a.timestamp))
                    .filter(t => !isNaN(t));
  if (!times.length) { hide(); return; }
  var minT = Math.min.apply(null, times);
  var maxT = Math.max.apply(null, times);
  var bucketMs = pickBucketMs(maxT - minT);
  var buckets = [];
  alerts.forEach(a => {
    var t = Date.parse(a.timestamp);
    if (isNaN(t)) return;
    var idx = Math.floor((t - minT) / bucketMs);
    a.bucketIdx = idx;
    buckets[idx] = buckets[idx] || { start:minT+idx*bucketMs, count:0,
                                     sev:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0} };
    buckets[idx].count++;
    buckets[idx].sev[a.severity]++;
  });
  // SVG <g><rect> per bucket, height ∝ count, segments per severity
}
```

**Click behavior:** clicking a bar calls
`siemSetTimeRange(bucket.start, bucket.start + bucketMs)` (§1.4) which
filters the alerts table.

**Visual:** SVG, no chart library. Stacked bars, severity color from
`SEV_CONFIG`. Active bucket gets `stroke:var(--accent); stroke-width:2`.

**Files touched:** index.html (insert section), js/siem.js (new
`siemRenderTimelineHisto`, called from `siemHandleResult` after
`siemRenderAlertsTable`), css/style.css (`.siem-timeline`, `.siem-tlbar`,
`.siem-tltip`).

**Difficulty:** S–M (~150 LOC).

---

### 1.2 Top-N analytics widgets

**Layout:** Insert a `siem-topn-grid` section between the timeline (§1.1)
and the alerts table. CSS grid, `repeat(auto-fit, minmax(220px, 1fr))`.

**Widgets (all derived from current filtered alerts):**

| ID                     | Field getter           | Title              |
|------------------------|------------------------|--------------------|
| `siemTopIps`           | `a => a.ip`            | TOP SOURCE IPs     |
| `siemTopEndpoints`     | `a => a.endpoint`      | TOP ENDPOINTS      |
| `siemTopUserAgents`    | `a => a.ua` (extract)  | TOP USER-AGENTS    |
| `siemTopStatusCodes`   | `a => a.status`        | TOP STATUS CODES   |
| `siemTopAttackTypes`   | `a => a.type`          | TOP ATTACK TYPES   |
| `siemTopCountries`     | `a => a.geo?.country`  | TOP COUNTRIES      |

UA / status need to be extracted into the alert at parse time —
add to `siemClientSideAnalyze`:
```js
var uaM = line.match(/"([^"]+)"\s*$/);  // last quoted string
if (uaM) alert.ua = uaM[1];
var stM = line.match(/"\s+(\d{3})\s+/);
if (stM) alert.status = stM[1];
```

**Row template (each widget):**
```html
<div class="siem-topn-card">
  <div class="siem-topn-title">TOP SOURCE IPs</div>
  <div class="siem-topn-rows">
    <button class="siem-topn-row" data-field="ip" data-val="10.0.0.55">
      <span class="siem-topn-bar" style="width:67%"></span>
      <span class="siem-topn-val">10.0.0.55</span>
      <span class="siem-topn-count">42</span>
    </button>
    …
  </div>
</div>
```

**Click behavior:** `onclick="siemAppendKqlToken('ip','10.0.0.55')"` (§0.7
helper). Active filter row gets class `siem-topn-row-active`.

**Re-render:** call `siemRenderTopN(filteredAlerts)` from the END of
`siemRenderAlertsTableFiltered` so widgets reflect the live filtered set.

**Difficulty:** S (~120 LOC).

---

### 1.3 Geographic breakdown

Two phases:

**Phase A — bar list (cheap, ship first):**
- Reuse `siemTopCountries` widget from §1.2.
- Backfill `alert.geo` on demand: distinct IPs only, throttled to 5
  parallel `ipGeo()` calls.
- Display country code + count.

**Phase B — SVG world heat (later):**
- Use the public-domain Natural Earth lo-res world `<path>` set (~80 KB).
- Color each country by alert count (log-scaled).
- Click a country → `siemAppendKqlToken('cc', 'US')`.

**Geo-enrichment plumbing:**
```js
async function siemEnrichGeoForAlerts(alerts, opts) {
  var distinct = [...new Set(alerts.map(a=>a.ip).filter(Boolean))];
  var concurrency = (opts && opts.concurrency) || 5;
  var queue = distinct.slice();
  async function worker() {
    while (queue.length) {
      var ip = queue.shift();
      var g  = await ipGeo(ip);
      if (g) alerts.filter(a=>a.ip===ip).forEach(a => {
        a.geo = { country: g.country, cc: g.countryCode, city: g.city };
        a.asn = g.asn ? { asn: g.asn, org: g.org } : null;
      });
    }
  }
  await Promise.all(Array.from({length:concurrency}, worker));
}
```

**Trigger:** auto on analysis completion if alerts > 0 and < 200 distinct
IPs (avoid quota burn). Otherwise manual via "Enrich geo" button.

**Difficulty:** Phase A: S. Phase B: M.

---

### 1.4 Time-range filter

**DOM:** add a chip group above the timeline. Options: `5m / 15m / 1h /
6h / 24h / 7d / All / Custom`. Custom opens two `<input type=datetime-local>`.

**State:**
```js
SIEM_TIMERANGE = {
  active: false,
  startMs: null,
  endMs:   null,
  preset:  'all',         // '5m'|'15m'|'1h'|'6h'|'24h'|'7d'|'all'|'custom'
};
```

**Filter integration:** modify `siemFilterAlerts` (siem.js L691) to also
respect `SIEM_TIMERANGE` after the token AND-pass:
```js
function siemFilterAlerts(alerts) {
  var passed = alerts.filter(/* existing token logic */);
  if (SIEM_TIMERANGE.active) {
    passed = passed.filter(a => {
      var t = Date.parse(a.timestamp);
      return !isNaN(t) && t >= SIEM_TIMERANGE.startMs && t < SIEM_TIMERANGE.endMs;
    });
  }
  return passed;
}
```

**Visual indicator:** active range shown as a chip in `siemFilterChips`
with an X to clear.

**Difficulty:** S (~80 LOC).

---

## 2 · Detection coverage

### 2.1 MITRE ATT&CK mapping

**Static lookup:**
```js
var MITRE_MAP = {
  'SQL Injection':              { id:'T1190', name:'Exploit Public-Facing App', tactic:'Initial Access' },
  'Cross-Site Scripting (XSS)': { id:'T1059.007', name:'Command/Scripting: JS', tactic:'Execution' },
  'Directory Brute Force':      { id:'T1595.003', name:'Active Scanning: Wordlist', tactic:'Reconnaissance' },
  'Security Scanner':           { id:'T1595.002', name:'Active Scanning: Vuln Scan', tactic:'Reconnaissance' },
  'High-Frequency Requests':    { id:'T1499.002', name:'Endpoint DoS: Service Exhaustion', tactic:'Impact' },
  'Brute Force Login':          { id:'T1110',   name:'Brute Force', tactic:'Credential Access' },
  'Credential Stuffing':        { id:'T1110.004', name:'Credential Stuffing', tactic:'Credential Access' },
  'Honeypot Path':              { id:'T1083',   name:'File and Directory Discovery', tactic:'Discovery' },
  'Beacon Candidate':           { id:'T1071.001', name:'Application Layer Proto: Web', tactic:'C&C' },
  'Tor Exit Source':            { id:'T1090.003', name:'Multi-hop Proxy: Tor', tactic:'C&C' },
  'DGA Domain':                 { id:'T1568.002', name:'Dynamic Resolution: DGA', tactic:'C&C' },
};
```

**Where to apply:** in `siemHandleResult` after alerts come in, BEFORE
rendering: `alerts.forEach(a => a.mitre = MITRE_MAP[a.type] || null)`.

**Render:** add a small grey pill in the alerts-table "Attack Type" cell:
```html
<strong>SQL Injection</strong>
<span class="siem-mitre" title="Exploit Public-Facing App">T1190</span>
```
Tooltip = `mitre.name + ' · ' + mitre.tactic`. Clicking the pill opens
`https://attack.mitre.org/techniques/{id}/` in a new tab.

**Difficulty:** XS (~30 LOC + lookup table).

---

### 2.2 Beacon / C2 detection

**Algorithm (per-IP, per-endpoint):**
```js
function siemDetectBeacons(rawEvents) {
  // rawEvents: [{ ip, endpoint, t (ms) }]
  var groups = {};
  rawEvents.forEach(e => {
    if (!e.ip || !e.endpoint || isNaN(e.t)) return;
    var k = e.ip + '|' + e.endpoint;
    (groups[k] = groups[k] || []).push(e.t);
  });
  var alerts = [];
  Object.keys(groups).forEach(k => {
    var ts = groups[k].sort((a,b)=>a-b);
    if (ts.length < 6) return;       // not enough samples
    var deltas = [];
    for (var i=1;i<ts.length;i++) deltas.push(ts[i]-ts[i-1]);
    var mean = deltas.reduce((a,b)=>a+b,0) / deltas.length;
    if (mean < 1000) return;          // sub-second = noise
    var variance = deltas.reduce((s,d)=>s+(d-mean)*(d-mean),0)/deltas.length;
    var stddev = Math.sqrt(variance);
    var jitter = stddev / mean;       // coefficient of variation
    if (jitter < 0.15) {              // < 15% jitter = suspiciously regular
      var [ip, endpoint] = k.split('|');
      alerts.push({
        type: 'Beacon Candidate',
        severity: jitter < 0.05 ? 'CRITICAL' : 'HIGH',
        ip: ip, endpoint: endpoint, timestamp: new Date(ts[0]).toISOString(),
        evidence: ts.length+' hits, mean Δt='+(mean/1000).toFixed(1)+'s, jitter='+
                  (jitter*100).toFixed(1)+'%',
        risk_score: Math.round(85 - jitter * 200),
        patterns: ['jitter<0.15'],
        correlation_note: 'Regularly-timed callbacks suggest C2 beaconing',
        tags: ['beacon-candidate']
      });
    }
  });
  return alerts;
}
```

**Plumbing:** during `siemClientSideAnalyze`, build a parallel `events[]`
array with `{ip, endpoint, t}` for every parsed line that has all three.
After main detection, call `alerts = alerts.concat(siemDetectBeacons(events))`.

**Tunables (top of siem.js):**
```js
var BEACON_MIN_SAMPLES   = 6;
var BEACON_JITTER_THRESH = 0.15;
var BEACON_MIN_INTERVAL  = 1000; // ms
```

**Difficulty:** M (~80 LOC).

---

### 2.3 Honeypot path hits

**Path list (top of siem.js, near `_CLIENT_BRUTE`):**
```js
var HONEYPOT_PATHS = [
  { re: /^\/\.env(?:\.|$)/i,                  sev:'CRITICAL', label:'.env access' },
  { re: /^\/\.git\/(?:HEAD|config|index)/i,   sev:'CRITICAL', label:'.git directory' },
  { re: /^\/\.aws\/credentials/i,             sev:'CRITICAL', label:'AWS credentials' },
  { re: /^\/\.ssh\/(?:id_rsa|authorized_keys)/i, sev:'CRITICAL', label:'SSH keys' },
  { re: /^\/wp-(?:admin|login)\.php/i,        sev:'HIGH',     label:'WordPress admin' },
  { re: /^\/phpmyadmin/i,                     sev:'HIGH',     label:'phpMyAdmin' },
  { re: /^\/admin(?:\/|$)/i,                  sev:'MEDIUM',   label:'/admin' },
  { re: /^\/server-status/i,                  sev:'HIGH',     label:'Apache server-status' },
  { re: /^\/phpinfo\.php/i,                   sev:'HIGH',     label:'phpinfo' },
  { re: /^\/_ignition\/execute-solution/i,    sev:'CRITICAL', label:'Laravel Ignition RCE' },
  { re: /^\/api\/v1\/swagger/i,               sev:'LOW',      label:'Swagger UI' },
  { re: /^\/(?:console|jenkins|grafana)\b/i,  sev:'MEDIUM',   label:'Admin console' },
  { re: /^\/\.DS_Store/i,                     sev:'LOW',      label:'.DS_Store' },
];
```

**Detection:** in `siemClientSideAnalyze` after the brute-force check:
```js
if (ep) {
  HONEYPOT_PATHS.forEach(h => {
    if (h.re.test(ep)) alerts.push({
      type: 'Honeypot Path: ' + h.label,
      severity: h.sev, ip: ip, timestamp: ts, endpoint: ep,
      evidence: line.slice(0, 200),
      risk_score: { CRITICAL:90, HIGH:75, MEDIUM:55, LOW:30 }[h.sev],
      patterns: ['honeypot:'+h.label],
      tags: ['recon']
    });
  });
}
```

**MITRE:** entry already in `MITRE_MAP['Honeypot Path']` (§2.1) — but
since type is `'Honeypot Path: X'`, do a `startsWith` match in the lookup.

**Difficulty:** XS (~40 LOC).

---

### 2.4 DGA / suspicious-domain detector

**Used when alerts/events contain `domain` or `host` field (DNS / proxy
logs). Skip silently if no domain data present.**

**Shannon entropy:**
```js
function shannonEntropy(s) {
  if (!s) return 0;
  var counts = {};
  for (var i=0;i<s.length;i++) counts[s[i]] = (counts[s[i]]||0)+1;
  var H = 0, n = s.length;
  Object.values(counts).forEach(c => { var p = c/n; H -= p * Math.log2(p); });
  return H;
}
```

**Heuristics (combined score, 0–100):**
```js
function dgaScore(domain) {
  var labels = domain.toLowerCase().split('.');
  var sld = labels[labels.length-2] || '';
  var tld = labels[labels.length-1] || '';
  var entropy = shannonEntropy(sld);
  var vowelRatio = (sld.match(/[aeiou]/g)||[]).length / Math.max(1, sld.length);
  var digitRatio = (sld.match(/\d/g)||[]).length     / Math.max(1, sld.length);
  var consec     = /[bcdfghjklmnpqrstvwxyz]{4,}/.test(sld);
  var sketchyTld = /^(xyz|top|click|link|tk|ml|ga|cf|gq|ru|cn|su)$/.test(tld);
  var score = 0;
  if (entropy > 3.5) score += 40;
  else if (entropy > 3.0) score += 25;
  if (sld.length > 12) score += 15;
  if (vowelRatio < 0.25) score += 15;
  if (digitRatio > 0.3) score += 10;
  if (consec) score += 10;
  if (sketchyTld) score += 15;
  return Math.min(100, score);
}
```

**Threshold:** `score >= 60` → alert with severity `HIGH`,
type `DGA Domain`, evidence = full domain + score breakdown.

**Difficulty:** M (~100 LOC).

---

### 2.5 Failed-login by username

**Username extraction (best-effort):**
```js
function extractUsername(line) {
  // POST body in URL: ?user=alice&pass=...
  var m = line.match(/[?&](?:user(?:name)?|email|login|u)=([^&\s"]+)/i);
  if (m) return decodeURIComponent(m[1]).toLowerCase();
  // JSON: "username":"alice"
  m = line.match(/"(?:username|user|email|login)"\s*:\s*"([^"]+)"/i);
  if (m) return m[1].toLowerCase();
  return null;
}

function isAuthFail(line) {
  return /\b(401|403)\b/.test(line) ||
         /(invalid|incorrect|failed)\s+(password|login|credentials)/i.test(line);
}
```

**Detection:**
```js
var perUser = {};   // user -> { ips:Set, ts:[], count:N }
events.forEach(e => {
  var u = extractUsername(e.line);
  if (!u || !isAuthFail(e.line)) return;
  var x = perUser[u] = perUser[u] || { ips:new Set(), ts:[], count:0 };
  x.ips.add(e.ip); x.ts.push(e.t); x.count++;
});
Object.entries(perUser).forEach(([u, x]) => {
  if (x.count >= 5 && x.ips.size >= 3) {
    alerts.push({
      type: 'Credential Stuffing',
      severity: x.ips.size >= 10 ? 'CRITICAL' : 'HIGH',
      ip: null, endpoint: null,
      evidence: x.count+' failed logins for "'+u+'" from '+x.ips.size+' distinct IPs',
      risk_score: Math.min(95, 50 + x.ips.size*3 + x.count),
      patterns: ['per-user-fanout'], tags: ['credential-stuffing']
    });
  } else if (x.count >= 10 && x.ips.size === 1) {
    alerts.push({
      type: 'Brute Force Login',
      severity: 'HIGH', ip: [...x.ips][0], endpoint: null,
      evidence: x.count+' failed logins for "'+u+'" from single IP',
      risk_score: Math.min(85, 40 + x.count),
      patterns: ['per-user-from-one-ip'], tags: ['brute-force']
    });
  }
});
```

**Difficulty:** S (~70 LOC).

---

### 2.6 Anomaly score per IP

Z-scores across four metrics, summed and clamped:

```js
function siemAnomalyScores(events) {
  // events: [{ip, t, line, status, size}]
  var byIp = {};
  events.forEach(e => {
    if (!e.ip) return;
    var x = byIp[e.ip] = byIp[e.ip] || { reqs:0, sizes:[], paths:new Set(),
                                          status:{}, firstT:Infinity, lastT:0 };
    x.reqs++;
    if (e.size) x.sizes.push(parseInt(e.size,10));
    if (e.endpoint) x.paths.add(e.endpoint);
    var s = e.status || 'unknown';
    x.status[s] = (x.status[s]||0)+1;
    x.firstT = Math.min(x.firstT, e.t);
    x.lastT  = Math.max(x.lastT, e.t);
  });
  var ips = Object.keys(byIp);
  var rpm = ips.map(ip => {
    var x = byIp[ip];
    var dur = Math.max(1, (x.lastT - x.firstT) / 60000);
    return x.reqs / dur;
  });
  function zArr(arr) {
    var n = arr.length || 1;
    var mu = arr.reduce((a,b)=>a+b,0)/n;
    var sd = Math.sqrt(arr.reduce((s,v)=>s+(v-mu)*(v-mu),0)/n) || 1;
    return arr.map(v => (v - mu) / sd);
  }
  var rpmZ = zArr(rpm);
  // …repeat for path-cardinality, avg size, status-skew (entropy)
  ips.forEach((ip,i) => {
    byIp[ip].anomaly = Math.min(100, Math.max(0,
      rpmZ[i]*15 + pathZ[i]*15 + sizeZ[i]*10 + statusZ[i]*15 + 50));
  });
  return byIp;
}
```

**Render:** new column in alerts table "Anomaly" showing the IP's score,
or a separate widget "Anomalous IPs" listing IPs with anomaly ≥ 70.

**Difficulty:** M (~120 LOC).

---

### 2.7 Long-tail / rare-value detection

For each `(field, value)` pair, count occurrences. If count == 1 in a
field with > 100 events, emit an INFO/LOW alert highlighting that pair
as anomalous.

Fields to audit: `status`, `method`, `cc` (country), `ua`.

```js
function siemFindRareValues(events) {
  var fieldCounts = { status:{}, method:{}, ua:{}, cc:{} };
  events.forEach(e => Object.keys(fieldCounts).forEach(f => {
    var v = e[f]; if (!v) return;
    fieldCounts[f][v] = (fieldCounts[f][v]||0)+1;
  }));
  var alerts = [];
  Object.keys(fieldCounts).forEach(f => {
    var counts = fieldCounts[f];
    var total = Object.values(counts).reduce((a,b)=>a+b,0);
    if (total < 100) return;          // too small to call something rare
    Object.entries(counts).forEach(([v,c]) => {
      if (c === 1) {
        alerts.push({
          type: 'Rare Value', severity: 'LOW',
          evidence: f+'='+v+' occurs only once across '+total+' events',
          patterns: ['rare:'+f], tags: ['anomaly']
        });
      }
    });
  });
  return alerts;
}
```

**Difficulty:** S (~50 LOC).

---

## 3 · Threat-intel enrichment

### 3.1 IP reputation lookup

**Plumbing:**
```js
async function siemEnrichIpReputation(alerts, opts) {
  var cache = JSON.parse(localStorage.getItem('sp_siem_threatintel_cache')||'{}');
  var TTL = 24 * 3_600_000;
  var distinct = [...new Set(alerts.map(a=>a.ip).filter(Boolean))];
  var queue = distinct.filter(ip =>
    !cache[ip] || (Date.now() - cache[ip].when) > TTL
  );
  var concurrency = (opts && opts.concurrency) || 4;
  async function worker() {
    while (queue.length) {
      var ip = queue.shift();
      var [uh, tf] = await Promise.all([
        urlHausLookup(ip),    // network.js
        threatFoxLookup(ip),  // network.js
      ]);
      var hit = (uh && uh.found) || (tf && tf.found);
      cache[ip] = {
        when: Date.now(),
        urlhaus: uh && uh.found ? { online:uh.online, threat:uh.threat } : null,
        threatfox: tf && tf.found ? { count:tf.iocs.length, type:tf.iocs[0].threat_type } : null,
      };
    }
  }
  await Promise.all(Array.from({length:concurrency}, worker));
  localStorage.setItem('sp_siem_threatintel_cache', JSON.stringify(cache));
  // Apply to alerts
  alerts.forEach(a => {
    var c = a.ip && cache[a.ip];
    if (!c) return;
    if (c.urlhaus || c.threatfox) {
      (a.tags = a.tags || []).push('known-bad');
      a.threatIntel = { urlhaus: c.urlhaus, threatfox: c.threatfox };
      // Bump severity
      var ord = SEV_CONFIG[a.severity].order;
      if (ord < 3) a.severity = 'HIGH';
      if (ord < 4 && c.urlhaus && c.urlhaus.online > 0) a.severity = 'CRITICAL';
    }
  });
}
```

**UI:** red "KNOWN-BAD" badge in the alerts-row IP cell when
`alert.threatIntel` is set; tooltip shows source.

**Difficulty:** S (~80 LOC).

---

### 3.2 Tor exit-node detection

```js
async function siemLoadTorExits() {
  var cached = JSON.parse(localStorage.getItem('sp_siem_tor_exits')||'null');
  if (cached && (Date.now() - cached.when) < 3_600_000) return new Set(cached.set);
  try {
    var r = await fetch('https://check.torproject.org/torbulkexitlist');
    if (!r.ok) return new Set();
    var txt = await r.text();
    var arr = txt.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    localStorage.setItem('sp_siem_tor_exits',
      JSON.stringify({ when:Date.now(), set:arr }));
    return new Set(arr);
  } catch(e) { return new Set(); }
}

async function siemTagTorExits(alerts) {
  var exits = await siemLoadTorExits();
  alerts.forEach(a => {
    if (a.ip && exits.has(a.ip)) {
      (a.tags = a.tags || []).push('tor');
      a.correlation_note = (a.correlation_note ? a.correlation_note+' · ' : '')
                         + 'Source IP is a known Tor exit node';
    }
  });
}
```

**UI:** purple `TOR` chip in the alerts IP cell when tagged.

**Difficulty:** XS (~40 LOC).

---

### 3.3 ASN / hosting classification

```js
async function siemEnrichAsn(alerts) {
  var distinct = [...new Set(alerts.map(a=>a.ip).filter(Boolean))];
  // Reuse classifyTarget — it relies on bgp/geo data, so call ipGeo first
  await Promise.all(distinct.map(async ip => {
    var R = {};
    R.geo = await ipGeo(ip);
    var c = classifyTarget(ip, R);
    alerts.filter(a=>a.ip===ip).forEach(a => {
      a.asn  = R.geo && { asn: R.geo.asn, org: R.geo.org };
      a.asnKind = c.kind;          // 'cdn'|'cloud'|'anycast-dns'|'normal'
      a.asnProv = c.provider;
      if (c.kind !== 'normal' && c.provider !== 'unknown')
        (a.tags = a.tags || []).push('asn:'+c.provider.toLowerCase());
    });
  }));
}
```

**UI:** small grey provider tag next to IP: `[AWS]`, `[Cloudflare]`,
`[Hetzner]`. Same colors as the Network Recon classifier banner.

**Difficulty:** S (~60 LOC).

---

## 4 · Workflow & UX

### 4.1 Saved searches

**Storage shape:** `localStorage.sp_siem_saved_searches`:
```json
[{"name":"HTTP errors from POST","query":"method:POST status:>=400",
  "when":1714000000000}]
```

**API:**
```js
function siemSavedSearches() {
  return JSON.parse(localStorage.getItem('sp_siem_saved_searches')||'[]');
}
function siemSaveSearch(name, query) {
  var arr = siemSavedSearches();
  arr = arr.filter(s => s.name !== name);
  arr.unshift({ name:name, query:query, when:Date.now() });
  localStorage.setItem('sp_siem_saved_searches', JSON.stringify(arr.slice(0,50)));
  siemRenderSavedDropdown();
}
function siemDeleteSearch(name) { /* … */ }
function siemApplySaved(name) {
  var s = siemSavedSearches().find(x=>x.name===name);
  if (!s) return;
  document.getElementById('siemSearchInput').value = s.query;
  siemApplySearch();
}
```

**DOM:** add a small dropdown button beside `siemSearchClear`:
```html
<div class="siem-saved-wrap">
  <button class="siem-saved-btn" onclick="siemSavedToggle()">★ Saved ▾</button>
  <div id="siemSavedDropdown" class="siem-saved-dropdown" style="display:none">
    <button class="siem-saved-add" onclick="siemSavedAddCurrent()">+ Save current query</button>
    <div id="siemSavedList"></div>
  </div>
</div>
```

**Difficulty:** S (~80 LOC + CSS).

---

### 4.2 Click-to-filter

Wrap clickable values in the alerts table and Top-N widgets with
`<button class="siem-filterable" data-field="ip" data-val="10.0.0.55">`.

Single delegated handler:
```js
document.addEventListener('click', e => {
  var t = e.target.closest('.siem-filterable');
  if (!t) return;
  e.stopPropagation();
  siemAppendKqlToken(t.dataset.field, t.dataset.val);
});
```

**Affected cells (in `siemRenderAlertsTableFiltered`):** IP, severity badge,
status code, method, endpoint, country tag.

**Affects helper:** `siemAppendKqlToken` from §0.7.

**Difficulty:** S (~40 LOC modification).

---

### 4.3 False-positive dismissal

**Storage:**
```json
{ "<sig>": { "reason": "internal scanner", "when": 1714000000000 } }
```

**API:**
```js
function siemDismissAlert(alert, reason) {
  var sig = siemAlertSignature(alert);
  var d = JSON.parse(localStorage.getItem('sp_siem_dismissed')||'{}');
  d[sig] = { reason: reason || 'manual', when: Date.now() };
  localStorage.setItem('sp_siem_dismissed', JSON.stringify(d));
  siemRefreshAlertsView();
}
function siemUndoDismiss(sig) { /* … */ }
function siemDismissedSet() {
  return JSON.parse(localStorage.getItem('sp_siem_dismissed')||'{}');
}
```

**Filter integration (siemFilterAlerts):**
```js
var dismissed = siemDismissedSet();
var showDismissed = document.getElementById('siemShowDismissed').checked;
passed = passed.filter(a => {
  var sig = siemAlertSignature(a);
  if (dismissed[sig]) {
    if (!showDismissed) return false;
    a.dismissed = true;
    a.dismissReason = dismissed[sig].reason;
  }
  return true;
});
```

**Render:** dismissed rows get class `siem-row-dismissed` (40% opacity,
strikethrough on attack-type cell, dim badges). Each row has a "✓"
dismiss / "↺" undo button.

**Difficulty:** M (~120 LOC).

---

### 4.4 Baseline diff

**Snapshot on demand:**
```js
function siemSetBaseline() {
  var alerts = siemRenderAlertsTable._cache || [];
  var sigs = alerts.map(siemAlertSignature);
  localStorage.setItem('sp_siem_baseline',
    JSON.stringify({ when: Date.now(), signatures: sigs }));
  showToast('Baseline saved — '+sigs.length+' alerts', 'success');
}

function siemMarkNewSinceBaseline(alerts) {
  var b = JSON.parse(localStorage.getItem('sp_siem_baseline')||'null');
  if (!b) return;
  var seen = new Set(b.signatures);
  alerts.forEach(a => {
    if (!seen.has(siemAlertSignature(a))) a.isNew = true;
  });
}
```

**Render:** `isNew` rows get a green left-border + "NEW" pill.

**UI:** add buttons next to the "DETECTED THREATS" title:
```html
<button onclick="siemSetBaseline()">Set Baseline</button>
<button onclick="siemClearBaseline()">Clear</button>
<span class="siem-baseline-info" id="siemBaselineInfo"></span>
```

**Difficulty:** S (~60 LOC).

---

### 4.5 Export alerts

Three formats, all built from current FILTERED alert set
(`siemRenderAlertsTable._cache` post-filter):

```js
function siemExportCsv(alerts) {
  var cols = ['severity','type','ip','timestamp','endpoint','risk_score','mitre.id'];
  var lines = [cols.join(',')];
  alerts.forEach(a => {
    lines.push(cols.map(c => {
      var v = c.includes('.') ? c.split('.').reduce((o,k)=>o&&o[k], a) : a[c];
      v = v == null ? '' : String(v).replace(/"/g,'""');
      return /[,"\n]/.test(v) ? '"'+v+'"' : v;
    }).join(','));
  });
  return lines.join('\n');
}
function siemExportJsonAlerts(alerts) { return JSON.stringify(alerts, null, 2); }
function siemExportSarif(alerts) { /* extend export.js buildSarif */ }

function siemDownload(name, mime, content) {
  var blob = new Blob([content], { type: mime });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
}
```

**UI:** button group near the alerts-table title:
`Export ▾` → CSV / JSON / SARIF.

**Difficulty:** S (~80 LOC).

---

### 4.6 Event drill-down panel

**UX:** clicking a source IP in the alerts table opens a right-side
slide-over showing every event from that IP (chronological), all paths
hit, all UAs used, status-code breakdown, anomaly score (§2.6),
threat-intel summary (§3.1), ASN/geo (§3.3).

**Plumbing requirement:** the analyzer must keep the parsed event set,
not just the alert set. Add to `SIEM` singleton:
```js
SIEM.lastEvents = events;        // [{ip, endpoint, t, status, ua, line}]
```

**Render:** new `<aside id="siemDrilldown" class="siem-drilldown">` fixed
to right edge. Six sub-panels: Events table · Path histogram · UA list ·
Status pie · Threat intel · Map snippet.

**Close:** Esc key, ✕ button, click-outside.

**Difficulty:** M–L (~250 LOC).

---

## 5 · Detection engineering

### 5.1 Custom-rule editor

**Storage:** `sp_siem_custom_rules`:
```json
[{
  "id":      "cust-l5q3pn",
  "name":    "GitHub token leak",
  "regex":   "ghp_[A-Za-z0-9]{36}",
  "flags":   "g",
  "field":   "any",
  "severity":"CRITICAL",
  "mitre":   "T1552.001",
  "desc":    "Hard-coded GitHub PAT",
  "enabled": true
}]
```

**Detection integration:** at the start of `siemClientSideAnalyze`:
```js
var customRules = (JSON.parse(localStorage.getItem('sp_siem_custom_rules')||'[]'))
  .filter(r => r.enabled).map(r => ({
    ...r, _re: new RegExp(r.regex, r.flags || 'i')
  }));
// per-line:
customRules.forEach(r => {
  if (r._re.test(line)) alerts.push({
    type: r.name, severity: r.severity, ip: ip, timestamp: ts, endpoint: ep,
    evidence: line.slice(0,200),
    risk_score: { CRITICAL:90, HIGH:75, MEDIUM:55, LOW:30, INFO:10 }[r.severity],
    mitre: r.mitre ? { id: r.mitre, name:'(custom)', tactic:'(custom)' } : null,
    customRuleId: r.id
  });
});
```

**Editor UI:** modal with table of rules + "Add rule" button.
Form: name (str) · regex (str, validated via `new RegExp`) · flags
(checkbox: i,g,m,s) · severity (select) · MITRE id (str) · description.

**Live test:** the modal has a "test against current logs" button that
shows match count before saving.

**Difficulty:** M (~250 LOC + modal CSS).

---

### 5.2 SIGMA-lite import

**Supported subset of SIGMA YAML:**
```yaml
title:     SQLi attempt in URL
id:        deadbeef-…
level:     high
detection:
  selection:
    cs-uri-query|contains:
      - "' OR '1'='1"
      - 'UNION SELECT'
  condition: selection
tags:
  - attack.t1190
```

**Parsing approach:** ship a tiny YAML parser (≈300 LOC) OR require user
to paste pre-converted JSON. Recommendation: minimal YAML → object parser
that handles only mappings, sequences, and quoted/unquoted scalars
(no anchors, no flow style).

**Compilation:**
```js
function compileSigmaRule(parsed) {
  // Each `selection.<field>|<modifier>: [vals…]` →
  //   compiledRule.tests.push({ field, modifier, vals, _re: regex|null });
  // condition: AND/OR/NOT of selection names
  return { id, level, tests, condition, tags };
}
function applySigmaRule(rule, line, fields) { /* eval condition */ }
```

**Modifiers to support:** `contains`, `startswith`, `endswith`, `re`, `cidr`
(IP CIDR match).

**UI:** "Import SIGMA" button → textarea modal, paste rule(s), validate,
save to `sp_siem_sigma_rules`.

**Difficulty:** L (~600 LOC).

---

### 5.3 Severity-escalation rules

Post-process pass after base detection:

```js
function siemApplyEscalations(alerts) {
  // Group by IP
  var byIp = {};
  alerts.forEach(a => {
    if (!a.ip) return;
    (byIp[a.ip] = byIp[a.ip] || []).push(a);
  });
  Object.keys(byIp).forEach(ip => {
    var hi = byIp[ip].filter(a => SEV_CONFIG[a.severity].order >= 3);
    if (hi.length < 5) return;
    // Sliding 10-min window?
    var ts = hi.map(a => Date.parse(a.timestamp)).filter(t=>!isNaN(t)).sort();
    if (!ts.length) return;
    var hot = false;
    for (var i=4;i<ts.length;i++) if (ts[i] - ts[i-4] <= 600_000) hot = true;
    if (!hot) return;
    alerts.push({
      type: 'Escalated: Multi-Hit Source',
      severity: 'CRITICAL',
      ip: ip, timestamp: hi[0].timestamp, endpoint: null,
      evidence: hi.length+' HIGH+ alerts within 10 min from same IP',
      risk_score: 95,
      patterns: ['escalation:multi-hit'],
      correlation_note: 'Promoted from individual HIGH alerts'
    });
  });
}
```

Tunables exposed at top of file:
`ESCALATION_MIN_ALERTS = 5`, `ESCALATION_WINDOW_MS = 600_000`.

**Difficulty:** S (~60 LOC).

---

## 6 · Build order (recommended)

Each milestone is internally cohesive — the items inside share state /
helpers, so building them together is much cheaper than scattered.

### Milestone A — UX uplift
*Adds visible structure; no new detection logic. Highest user-perceived
ROI.*

1. §0.7 helpers (signature, append-token, bucket-by-time, top-N)
2. §1.4 time-range filter
3. §1.1 time histogram
4. §1.2 top-N widgets
5. §4.2 click-to-filter (depends on #4)
6. §2.1 MITRE mapping (table + render)
7. §4.1 saved searches
8. §2.3 honeypot paths

### Milestone B — Enrichment
*Reuses `network.js`. Brings external context onto each alert.*

9.  §3.3 ASN classification
10. §3.2 Tor exit detection
11. §3.1 IP reputation lookup
12. §1.3 phase A (country bar list — depends on §3.3 enrichment)

### Milestone C — Detection depth

13. §2.2 beacon detection
14. §2.5 failed-login by username
15. §2.4 DGA detector (only if user pastes DNS-style logs)
16. §2.6 anomaly score
17. §5.3 severity-escalation rules

### Milestone D — Workflow polish

18. §4.3 false-positive dismissal
19. §4.4 baseline diff
20. §4.5 export alerts (CSV/JSON/SARIF)
21. §4.6 event drill-down

### Milestone E — Long tail

22. §2.7 rare-value detection
23. §1.3 phase B (SVG world heat map)
24. §5.1 custom-rule editor
25. §5.2 SIGMA-lite import

---

## 7 · Conventions every implementation must follow

1. **Always use `escHtml(...)` from `js/ui.js`** for any string interpolated
   into HTML. Never trust alert evidence / log lines / user query input.
2. **Persist to `localStorage` with the keys in §0.6**. No raw `localStorage`
   calls outside the small accessor functions defined per feature.
3. **Mutate alerts in place during the analyzer pipeline only**. After
   `siemHandleResult` runs, treat the alerts array as read-mostly; further
   filtering is done with `siemFilterAlerts`-style projections.
4. **Don't replace `siemFilterAlerts` — extend it**. Each new filter
   dimension (time range, dismissal, baseline-only) appends a stage to the
   existing AND chain.
5. **Render functions take filtered set + total**. `siemRenderTopN(filtered)`,
   `siemRenderTimelineHisto(filtered)`. Re-call them from
   `siemRenderAlertsTableFiltered`'s tail so they stay in sync with the
   active KQL/quick-filter/time-range/dismissal state.
6. **Network calls are best-effort**. Threat-intel / Tor list / geo
   enrichment must never block the initial render — kick them off after
   the first paint and re-render when each completes.
7. **Cache anything from a third-party API** to `localStorage` with an
   explicit TTL (§0.6), and always expose a "refresh" path.
8. **Severity bumps must be visible**. When enrichment escalates a
   severity (§3.1 known-bad), set `alert.severityBumped = true` and render
   a small ↑ glyph so the user sees that the engine adjusted.

---

## 8 · Out of scope for this roadmap

- Server-side / Node back-end (the existing `siemSubmit*` HTTP path is a
  thin wrapper; new features stay client-side until otherwise required).
- ML-based detection (anomaly score in §2.6 is statistics, not ML).
- Real-time streaming pipelines (the `_LIVE` simulator is sufficient
  until/unless WebSocket ingestion lands).
- Multi-tenant / RBAC concerns.
