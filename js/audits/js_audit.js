/**
 * ShadeParse — audits/js_audit.js
 * JavaScript / TypeScript-specific vulnerability patterns.
 * Requires: detectors.js (for runPats, lineOf, snip helpers).
 */

'use strict';

/* ── DOM XSS sinks ── */
var JS_DOM_SINKS = [
  {re:/innerHTML\s*=/g,              sink:'innerHTML',           title:'DOM XSS — innerHTML sink'},
  {re:/outerHTML\s*=/g,             sink:'outerHTML',            title:'DOM XSS — outerHTML sink'},
  {re:/document\.write\s*\(/g,      sink:'document.write()',     title:'DOM XSS — document.write sink'},
  {re:/\.insertAdjacentHTML\s*\(/g, sink:'insertAdjacentHTML()', title:'DOM XSS — insertAdjacentHTML sink'},
  {re:/eval\s*\(/g,                 sink:'eval()',               title:'DOM XSS — eval() sink'},
];

/* ── Express / Node reflected XSS ── */
var SAFE_ENCODE_FNS = 'he|escape|encodeHTML|escapeHtml|sanitize|DOMPurify|xss|htmlspecialchars|entities';

var JS_XSS_EXPRESS = [
  {
    re: new RegExp('res\\.send\\(\\s*`[^`]*\\$\\{(?!(?:' + SAFE_ENCODE_FNS + ')\\s*[.\\(])([a-zA-Z_$][\\w\\.]*)','gi'),
    title: 'Reflected/Stored XSS — res.send() with unescaped template literal expression',
    sev: 'critical',
    desc: 'res.send() renders a template literal with an interpolated variable as raw HTML.',
    fix: "const he = require('he');\nres.send(`<div>${he.encode(q)}</div>`);"
  },
  {re:/res\s*\.\s*send\s*\(\s*["']<[^"']*["']\s*\+\s*(?!he\.|escape|encodeHTML|escapeHtml|sanitize|DOMPurify)\w/gi, title:'Reflected XSS — res.send() HTML string concat', sev:'critical', desc:'HTML string concatenated with an unescaped variable.', fix:"res.send('<div>' + he.encode(userValue) + '</div>');"},
  {re:/html\s*\+=\s*`<[^`]*\$\{(?!(?:he|escape|encodeHTML|escapeHtml|sanitize|DOMPurify)\s*[.(])[^}]+\}/gi, title:'Stored XSS — unescaped variable appended to HTML accumulator', sev:'critical', desc:'Variable interpolated into HTML accumulator without escaping.', fix:"html += `<div>${he.encode(row.msg)}</div>`;"},
];

/* ── SQL Injection (JS/Node) ── */
var JS_SQL = [
  {re:/["'`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\s[^"'`]*["'`]\s*\+/gi, title:'SQL injection — string concat (JS)', sev:'critical', desc:'SQL query built with string concatenation.', fix:"db.query('SELECT * FROM t WHERE id=?',[id])"},
];

/* ── Command Injection (JS/Node) ── */
var JS_CMD = [
  {re:/exec\s*\(\s*["'`].*\+|execSync\s*\([^)]*\+/g, title:'Command injection — dynamic exec (JS)', sev:'critical', desc:'User input may reach shell exec.', fix:"spawn('cmd',[arg],{shell:false})"},
];

/* ── Prototype Pollution ── */
var JS_PROTO = [
  {re:/for\s*\(\s*(const|let|var)?\s*key\s+in\s+\w+\s*\)(?![^{]*hasOwnProperty)/g, title:'Prototype pollution — unsafe for..in merge', sev:'critical', desc:'Unsafe for..in merge can pollute Object.prototype.', fix:'Guard with hasOwnProperty or Object.keys().', confidence:85},
  {re:/Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|request\.|user\.)/g, title:'Prototype pollution — Object.assign with user input', sev:'critical', desc:'Object.assign with user input → pollution.', fix:'Validate/whitelist keys before merge.', confidence:80},
  {re:/\$\.extend\s*\(\s*true/g, title:'Prototype pollution — jQuery deep extend', sev:'critical', desc:'jQuery deep extend with user input → pollution.', fix:'Use lodash merge with prototype check.', confidence:90},
  {re:/\[["']__proto__["']\]|\.constructor\s*\[["']prototype["']\]/g, title:'Prototype pollution — direct __proto__ access', sev:'critical', desc:'Direct __proto__ access → pollution.', fix:'Reject objects with __proto__ keys.', confidence:95},
];

/* ── Logic / Auth ── */
var JS_LOGIC = [
  {re:/localStorage\.getItem\s*\(.*\)\s*===\s*["'](?:true|1|admin)['"]/g, title:'Authorization via localStorage (bypassable)', sev:'critical', desc:'Auth via localStorage is trivially bypassable.', fix:'const res = await fetch("/api/auth/check");\nif (!res.ok) redirect("/login");'},
  {re:/if\s*\(\s*(?:is_?admin|isAdmin|role\s*===\s*["']admin)\s*\)/g, title:'Client-side admin role check', sev:'high', desc:'Client-side role checks can be bypassed via DevTools.', fix:'// Validate roles server-side only'},
  {re:/window\.location\.href\s*=\s*(?:params\.get|location\.search|decodeURIComponent)/g, title:'Open Redirect — location.href from params', sev:'high', desc:'Setting location.href from URL params allows phishing.', fix:'const SAFE=["/dashboard","/home"];\nif(SAFE.includes(next)) window.location.href=next;'},
];

/* ── Insecure Storage ── */
var JS_STORAGE = [
  {re:/localStorage\.setItem\s*\(\s*["'][^"']*["']\s*,\s*(?:.*token|.*password|.*secret|.*jwt|.*auth)/gi, title:'Token/password stored in localStorage', sev:'high', desc:'Sensitive data in localStorage accessible to all JS on the page.'},
  {re:/sessionStorage\.setItem\s*\(\s*["'][^"']*["']\s*,\s*(?:.*token|.*password|.*jwt)/gi, title:'Token stored in sessionStorage', sev:'medium', desc:'sessionStorage exfiltrable via XSS.'},
  {re:/document\.cookie\s*=[^;](?!.*HttpOnly)(?!.*Secure)/gi, title:'Cookie set without Secure/HttpOnly flags', sev:'high', desc:'Cookies without Secure/HttpOnly stolen via sniffing or XSS.'},
];

/* ── Weak Crypto (JS) ── */
var JS_CRYPTO = [
  {re:/createHash\s*\(\s*["']md5["']\s*\)/g,      title:'MD5 used for hashing',                    sev:'high',     fix:"crypto.createHash('sha256').update(data).digest('hex')"},
  {re:/createHash\s*\(\s*["']sha1["']\s*\)/g,     title:'SHA-1 used for hashing',                  sev:'high',     fix:"crypto.createHash('sha256').update(data).digest('hex')"},
  {re:/Math\.random\s*\(\s*\)/g,                  title:'Math.random() for security tokens',        sev:'high',     fix:'crypto.getRandomValues(new Uint8Array(32))'},
  {re:/rejectUnauthorized\s*:\s*false/gi,          title:'TLS certificate verification disabled',   sev:'critical', fix:'// Remove rejectUnauthorized: false'},
  {re:/createCipheriv\s*\(\s*["'](?:des|rc4|aes-\d+-ecb)["']/gi, title:'Broken cipher algorithm (JS)', sev:'critical', fix:"crypto.createCipheriv('aes-256-gcm', key, iv)"},
];

/**
 * runJsAudit(code) → Array of findings
 * Runs JS/TS-specific checks. Also handles TypeScript (same patterns apply).
 */
function runJsAudit(code) {
  var F = [], lines = code.split('\n');

  // DOM XSS — only fire when a taint source is present
  if (/location\.(hash|search|href|pathname)|URLSearchParams|document\.referrer|window\.name|params\.get\(/.test(code)) {
    JS_DOM_SINKS.forEach(function(p) {
      var re = new RegExp(p.re.source, p.re.flags), m;
      while ((m = re.exec(code)) !== null) {
        var ln = lineOf(code, m.index);
        F.push({
          id: 'xss-js-' + p.sink.replace(/[^a-z]/gi, '-') + '-' + ln,
          type: 'XSS', title: p.title, sev: 'critical',
          loc: 'line ' + ln, line: ln,
          snippet: lines[ln - 1] ? lines[ln - 1].trim() : '',
          match: m[0],
          desc: 'User-controlled data may reach ' + p.sink + ' without sanitization.',
          remediation: { text: 'Use DOMPurify or textContent instead.', fix: 'el.innerHTML = DOMPurify.sanitize(untrustedInput);' },
          confidence: 90,
          taint: { source: 'location.hash / URLSearchParams', flow: ['unsanitized'], sink: p.sink }
        });
      }
    });
  }

  // Express XSS patterns
  JS_XSS_EXPRESS.forEach(function(p) {
    var re = new RegExp(p.re.source, p.re.flags), m;
    while ((m = re.exec(code)) !== null) {
      var ln = lineOf(code, m.index);
      F.push({
        id: 'xss-express-' + ln, type: 'XSS', title: p.title, sev: p.sev,
        loc: 'line ' + ln, line: ln,
        snippet: lines[ln - 1] ? lines[ln - 1].trim() : m[0],
        match: m[0].slice(0, 80), desc: p.desc,
        remediation: { text: 'HTML-encode all user-controlled data. Use `he` or `escape-html`.', fix: p.fix },
        confidence: 88,
        taint: { source: 'req.query / req.body / db row', flow: ['unsanitized'], sink: 'res.send()' }
      });
    }
  });

  F = F.concat(runPats(code, JS_SQL,     'INJECT',  'inject-js-sql',  null));
  F = F.concat(runPats(code, JS_CMD,     'INJECT',  'inject-js-cmd',  null));
  F = F.concat(runPats(code, JS_PROTO,   'PROTO',   'proto-js',       null));
  F = F.concat(runPats(code, JS_LOGIC,   'LOGIC',   'logic-js',       null));
  F = F.concat(runPats(code, JS_STORAGE, 'STORAGE', 'storage-js',     null));
  F = F.concat(runPats(code, JS_CRYPTO,  'CRYPTO',  'crypto-js',      null));

  return F;
}

/* TypeScript uses the same audit as JS */
function runTypeScriptAudit(code) {
  return runJsAudit(code);
}
