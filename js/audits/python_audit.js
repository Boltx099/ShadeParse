/**
 * ShadeParse — audits/python_audit.js
 * Python-specific vulnerability patterns.
 * Requires: detectors.js (for runPats, lineOf, snip helpers).
 */

'use strict';

/* ── SQL Injection ── */
var PY_SQL = [
  {re:/(?:cursor|conn|db|session|c|cur)\s*\.\s*execute\s*\(\s*f["'][^"']*\{/gi, title:'SQL Injection — f-string in execute()', sev:'critical', desc:'f-string SQL interpolation is injectable.', fix:'cursor.execute("SELECT * FROM t WHERE id = ?", (id,))'},
  {re:/(?:query|sql|stmt|statement)\s*=\s*f["'][^"'\n]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^"'\n]*\{/gi, title:'SQL Injection — f-string SQL query variable', sev:'critical', desc:'SQL query built with f-string interpolation → injectable when passed to execute().', fix:'cursor.execute("SELECT * FROM users WHERE username=?", (username,))'},
  {re:/(?:cursor|conn|db|session|c|cur)\s*\.\s*execute\s*\(\s*(?:query|sql|stmt|statement)\s*\)/gi, title:'SQL Injection — variable passed directly to execute()', sev:'high', desc:'A pre-built variable is passed to execute(). If assembled via f-string or concatenation, this is injectable.', fix:'Always use parameterized queries: cursor.execute("SELECT ... WHERE id=?", (val,))'},
  {re:/(?:cursor|conn|db|c|cur)\s*\.\s*execute\s*\([^)]*\.format\s*\(/gi, title:'SQL Injection — .format() in execute()', sev:'critical', desc:'.format() in SQL is injectable.', fix:'Use parameterized queries.'},
  {re:/(?:cursor|conn|db|c|cur)\s*\.\s*execute\s*\(\s*["'][^"']*["']\s*%\s*/gi, title:'SQL Injection — % formatting in execute()', sev:'critical', desc:'% formatting in SQL is injectable.', fix:'cursor.execute("SELECT * FROM t WHERE id = ?", (val,))'},
  {re:/(?:cursor|conn|db|session|c|cur)\s*\.\s*execute\s*\(\s*["'][^"']*["']\s*\+/gi, title:'SQL Injection — string concatenation in execute()', sev:'critical', desc:'String concatenation in SQL query → injectable.', fix:'Use parameterized queries with ? placeholders.'},
];

/* ── Command Injection ── */
var PY_CMD = [
  {re:/os\.system\s*\(\s*(?:f["']|[^"')]*\+)/gi, title:'Command Injection — os.system() dynamic', sev:'critical', desc:'os.system() with user input → OS command execution.', fix:'subprocess.run(["cmd", arg], shell=False)'},
  {re:/subprocess\s*\.\s*(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/gi, title:'Command Injection — subprocess shell=True', sev:'high', desc:'shell=True enables shell metacharacter injection.', fix:'subprocess.run(["cmd", arg], shell=False)'},
  {re:/os\.popen\s*\(\s*(?:f["']|[^"')]*\+)/gi, title:'Command Injection — os.popen() dynamic', sev:'critical', desc:'os.popen() with user input → command injection.', fix:'subprocess.run(["cmd", arg], capture_output=True)'},
  {re:/\beval\s*\(\s*(?:request\.|input\s*\(|os\.environ)/gi, title:'Code Injection — eval() external input', sev:'critical', desc:'eval() on user data = Remote Code Execution.', fix:'Never eval() user input.'},
  {re:/\bexec\s*\(\s*(?:request\.|input\s*\(|os\.environ)/gi, title:'Code Injection — exec() external input', sev:'critical', desc:'exec() on user data = Remote Code Execution.', fix:'Remove exec() on user input.'},
];

/* ── SSTI ── */
var PY_SSTI = [
  {re:/render_template_string\s*\(\s*(?:request\.[^\s,)]+|[^"'\)]*\+\s*(?:request|user_input|data|msg|q))/gi, title:'SSTI — render_template_string() user data', sev:'critical', desc:'User data as Jinja2 template → RCE.', fix:'render_template_string("<div>{{ q }}</div>", q=user_input)'},
  {re:/jinja2\.Template\s*\(\s*(?:request\.|f["'][^"']*\{[^}]*request|[^"'\)]*\+)/gi, title:'SSTI — Jinja2 Template() from user input', sev:'critical', desc:'Jinja2 template from user input → SSTI/RCE.', fix:'Use env.get_template() with file-based templates.'},
];

/* ── Insecure Deserialization ── */
var PY_DESERIAL = [
  {re:/pickle\.loads?\s*\(\s*(?:request\.|data|user_input|body|payload)/gi, title:'Insecure Deserialization — pickle.load()', sev:'critical', desc:'pickle on untrusted data = arbitrary RCE.', fix:'import json\ndata = json.loads(request.data)'},
  {re:/yaml\.load\s*\(\s*[^,)]+\)/gi, title:'Insecure Deserialization — yaml.load() unsafe', sev:'critical', desc:'yaml.load() without SafeLoader executes arbitrary Python.', fix:'yaml.safe_load(data)'},
  {re:/marshal\.loads?\s*\(\s*(?:request\.|data|user_input|body)/gi, title:'Insecure Deserialization — marshal.loads()', sev:'critical', desc:'marshal of untrusted data → RCE.', fix:'Use JSON for data interchange.'},
  {re:/jsonpickle\.decode\s*\(/gi, title:'Insecure Deserialization — jsonpickle.decode()', sev:'critical', desc:'jsonpickle.decode() can execute arbitrary code.', fix:'Use json.loads() for untrusted inputs.'},
];

/* ── Path Traversal ── */
var PY_PATH = [
  {re:/open\s*\(\s*(?:request\.\w+\.get\s*\(|f["'][^"']*\{[^}]*(?:request|filename|path))/gi, title:'Path Traversal — open() with request input', sev:'critical', desc:'open() with unvalidated params → read arbitrary files.', fix:'path = os.path.join(base, os.path.basename(input))\nif not path.startswith(base): abort(403)'},
  {re:/send_file\s*\(\s*(?:request\.|os\.path\.join\s*\([^)]*request)/gi, title:'Path Traversal — send_file() with request input', sev:'critical', desc:'Flask send_file() with user path → file disclosure.', fix:'Use werkzeug.utils.safe_join()'},
  {re:/\.save\s*\(\s*(?:os\.path\.join\s*\([^)]*(?:f\.filename|file\.filename|filename)|filename|path)\s*\)/gi, title:'Path Traversal — file.save() with unvalidated filename', sev:'critical', desc:'Saving an uploaded file using the raw f.filename allows path traversal (e.g. ../../etc/passwd).', fix:'from werkzeug.utils import secure_filename\nfilename = secure_filename(f.filename)\npath = os.path.join("uploads", filename)\nf.save(path)'},
  {re:/os\.path\.join\s*\([^)]*(?:f\.filename|file\.filename|request\.files[^)]*\.filename)\s*\)/gi, title:'Path Traversal — os.path.join() with raw uploaded filename', sev:'critical', desc:'os.path.join() with an unvalidated filename from the request allows directory traversal.', fix:'from werkzeug.utils import secure_filename\nfilename = secure_filename(request.files["file"].filename)'},
];

/* ── SSRF ── */
var PY_SSRF = [
  {re:/requests\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*(?:request\.\w+\.get|request\.args\.get|f["'][^"']*\{[^}]*request)/gi, title:'SSRF — requests library user-controlled URL', sev:'critical', desc:'HTTP to user URL → SSRF, internal network access.', fix:'ALLOWED = ["api.example.com"]\nif urlparse(url).hostname not in ALLOWED: abort(400)'},
  {re:/requests\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["']https?:\/\/(?:localhost|127\.0\.0\.1|internal\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/gi, title:'SSRF — requests to hardcoded internal/localhost URL', sev:'high', desc:'HTTP request targeting an internal network address.', fix:'Avoid internal URLs in application code.'},
  {re:/requests\s*\.\s*(?:get|post|put|delete|patch)\s*\([^)]*\)(?!\s*#[^\n]*timeout)(?![^)]*timeout\s*=)/gi, title:'Missing timeout on requests call — DoS risk', sev:'medium', desc:'requests without a timeout will hang indefinitely, causing thread exhaustion.', fix:'requests.get(url, timeout=5)'},
  {re:/urllib\s*\.\s*request\s*\.\s*urlopen\s*\(\s*(?:request\.\w+|f["'][^"']*\{[^}]*request)/gi, title:'SSRF — urllib.urlopen() user-controlled URL', sev:'critical', desc:'urlopen() with unvalidated URL → SSRF.', fix:'Validate and allowlist target URLs.'},
];

/* ── Configuration ── */
var PY_CONFIG = [
  {re:/app\.run\s*\([^)]*debug\s*=\s*True/gi, title:'Flask debug=True (RCE in production)', sev:'critical', desc:'Flask debug=True exposes a Python shell to visitors.', fix:'app.run(debug=os.getenv("FLASK_DEBUG","false")=="true")'},
  {re:/SECRET_KEY\s*=\s*["'][^"']{0,20}["']/gi, title:'Weak/hardcoded Flask SECRET_KEY', sev:'critical', desc:'Short SECRET_KEY allows session cookie forgery.', fix:'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]'},
  {re:/WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False/gi, title:'CSRF protection disabled', sev:'high', desc:'Disabling CSRF allows cross-site request forgery.', fix:'Do not disable CSRF in production.'},
  {re:/verify\s*=\s*False\b/gi, title:'SSL certificate verification disabled', sev:'critical', desc:'verify=False disables TLS validation → MITM.', fix:'Always use verify=True.'},
  {re:/ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/gi, title:'Django ALLOWED_HOSTS wildcard (*)', sev:'high', desc:'ALLOWED_HOSTS = ["*"] allows host header attacks.', fix:'ALLOWED_HOSTS = ["yourdomain.com"]'},
  {re:/DEBUG\s*=\s*True\b/gi, title:'Django DEBUG=True in production', sev:'critical', desc:'Django DEBUG=True exposes stack traces and settings.', fix:'DEBUG = bool(os.environ.get("DJANGO_DEBUG", False))'},
  {re:/(?:jsonify|json\.dumps|return)\s*\(\s*dict\s*\(\s*os\.environ\s*\)|os\.environ\s*\)/gi, title:'Environment variables exposed in HTTP response', sev:'critical', desc:'All environment variables (including secrets) are returned to the caller.', fix:'# Remove this endpoint or return only safe non-secret values'},
  {re:/(?:jsonify|json\.dumps)\s*\(\s*\{[^}]*(?:str\s*\(\s*e\s*\)|str\s*\(\s*err\s*\)|str\s*\(\s*error\s*\)|traceback)[^}]*\}\s*\)/gi, title:'Stack trace / exception detail exposed to user', sev:'high', desc:'Returning raw exception messages leaks internal implementation details to attackers.', fix:'return jsonify({"error": "An internal error occurred"}), 500'},
];

/* ── Cryptography ── */
var PY_CRYPTO = [
  {re:/hashlib\.md5\s*\(/gi, title:'Weak hashing — MD5', sev:'high', desc:'MD5 is broken for security use.', fix:'hashlib.sha256(data).hexdigest()'},
  {re:/hashlib\.sha1\s*\(/gi, title:'Weak hashing — SHA-1', sev:'high', desc:'SHA-1 is deprecated.', fix:'hashlib.sha256(data).hexdigest()'},
  {re:/\brandom\.(?:random|randint|choice|shuffle|randrange)\s*\(/gi, title:'Insecure randomness — random module', sev:'high', desc:'random is not cryptographically secure.', fix:'import secrets\nsecrets.token_hex(32)'},
  {re:/base64\.b64encode\s*\(\s*(?:[^)]*\+[^)]*\)|.*(?:password|secret|key|token|user)[^)]*\))/gi, title:'Weak crypto — base64 used as encryption', sev:'critical', desc:'base64 is encoding, not encryption — trivially reversible.', fix:'from cryptography.fernet import Fernet\nkey = Fernet.generate_key()\nf = Fernet(key)\ntoken = f.encrypt(data.encode())'},
  {re:/hashlib\.(?:md5|sha1|sha256|sha512)\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi, title:'Insecure password hashing — hashlib (not a KDF)', sev:'critical', desc:'hashlib hash functions are too fast for password hashing — easily brute-forced.', fix:'import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())'},
];

/* ── XSS ── */
var PY_XSS = [
  {re:/return\s+(?:f["'][^"']*<[^>]+>[^"']*\{[^}]*(?:request\.\w+\.get|q\b|name\b|msg\b|user_input))/gi, title:'XSS — Unescaped user input in HTML f-string', sev:'high', desc:'User input in HTML without escaping → reflected XSS.', fix:'from html import escape\nreturn f"<div>{escape(user_input)}</div>"'},
];

/* ── Open Redirect ── */
var PY_REDIRECT = [
  {re:/redirect\s*\(\s*(?:request\.\w+\.get|request\.args\.get|f["'][^"']*\{[^}]*request)/gi, title:'Open Redirect — redirect() user-controlled URL', sev:'high', desc:'Redirecting to user URL → phishing.', fix:'Validate redirect target is an internal safe URL.'},
];

/* ══════════════════════════════════════════
   EXPORTED AUDIT FUNCTION
══════════════════════════════════════════ */

/**
 * runPythonAudit(code) → Array of findings
 * Runs all Python-specific security checks against the given source code.
 */
function runPythonAudit(code) {
  var F = [];
  F = F.concat(runPats(code, PY_SQL,     'INJECT',  'inject-py-sql',  null));
  F = F.concat(runPats(code, PY_CMD,     'INJECT',  'inject-py-cmd',  null));
  F = F.concat(runPats(code, PY_SSTI,    'INJECT',  'inject-ssti',    null));
  F = F.concat(runPats(code, PY_DESERIAL,'DESERIAL', 'deserial-py',    null));
  F = F.concat(runPats(code, PY_PATH,    'PATH',    'path-py',        null));
  F = F.concat(runPats(code, PY_SSRF,    'SSRF',    'ssrf-py',        null));
  F = F.concat(runPats(code, PY_CONFIG,  'CONFIG',  'config-py',      null));
  F = F.concat(runPats(code, PY_CRYPTO,  'CRYPTO',  'crypto-py',      null));
  F = F.concat(runPats(code, PY_XSS,     'XSS',     'xss-py',         null));
  F = F.concat(runPats(code, PY_REDIRECT,'LOGIC',   'redirect-py',    null));
  return F;
}
