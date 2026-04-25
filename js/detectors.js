// ShadeParse — detectors.js
// UPGRADED v3.0: Universal multi-language security scanner
// Supports: JavaScript, TypeScript, Python, PHP, Java, Go, Ruby, C/C++, C#, Rust, Shell/Bash

'use strict';

/* ══════════════════════════════════════════
   LANGUAGE DETECTION (universal)
══════════════════════════════════════════ */

function detectLanguage(code) {
<<<<<<< HEAD
=======
  // Respect manually selected language from UI
  if (window._selectedLang) return window._selectedLang;

>>>>>>> 921b7bd (- IP and Domain/URL Scanner updated\n- Added New sources like wayback, BGP, crt.sh, etc to the scanners.\n- Added the restroing functionality to the history options.\n- Now the IP and URL/Domain Scanner can gather too much information about the Geo Location and other information.\n- The Code Auditor got improved.)
  var scores = { js:0, typescript:0, python:0, php:0, java:0, go:0, ruby:0, csharp:0, cpp:0, rust:0, shell:0, sql:0 };
  if (/\b(const|let|var)\s+\w+\s*=|function\s+\w+\s*\(|=>|require\s*\(|module\.exports|document\.|addEventListener/.test(code)) scores.js += 3;
  if (/\.then\s*\(|async\s+function|await\s+|Promise\.|\.catch\s*\(/.test(code)) scores.js += 2;
  if (/console\.(log|error)|process\.env|__dirname/.test(code)) scores.js += 2;
  if (/:\s*(string|number|boolean|any|void|never|unknown)\b|interface\s+\w+\s*\{|type\s+\w+\s*=|<T>|implements\s+\w+/.test(code)) scores.typescript += 4;
  if (/as\s+(string|number|any)|readonly\s+\w+|public\s+\w+\s*:|private\s+\w+\s*:/.test(code)) scores.typescript += 3;
  if (/def\s+\w+\s*\(|from\s+\w+\s+import|class\s+\w+\s*(\(|:)|if\s+__name__\s*==/.test(code)) scores.python += 3;
  if (/@app\.route|flask|django|fastapi|sqlalchemy|request\.(args|form|json)/.test(code)) scores.python += 2;
  if (/print\s*\(|self\.|elif\s+|lambda\s+\w+:/.test(code)) scores.python += 2;
  if (/<\?php|\$\w+\s*=|echo\s+|->|\bvar_dump\s*\(|\bdie\s*\(/.test(code)) scores.php += 4;
  if (/\$_GET|\$_POST|\$_REQUEST|\$_SESSION|\$_COOKIE|\$_SERVER/.test(code)) scores.php += 4;
  if (/mysqli_query|PDO::|mysql_query|pg_query/.test(code)) scores.php += 3;
  if (/public\s+(class|interface|enum)\s+\w+|import\s+java\.\w+|@Override|System\.out\.print/.test(code)) scores.java += 4;
  if (/@SpringBootApplication|@RequestMapping|@Autowired|@Entity|@Controller/.test(code)) scores.java += 3;
  if (/new\s+\w+\s*\(|throws\s+\w+Exception|instanceof\s+\w+/.test(code)) scores.java += 2;
  if (/^package\s+\w+|func\s+\w+\s*\(|import\s+\(|:=\s*|go\s+func|chan\s+\w+/.test(code)) scores.go += 4;
  if (/fmt\.Print|http\.HandleFunc|json\.Marshal|os\.Open|log\.Fatal|errors\.New/.test(code)) scores.go += 3;
  if (/def\s+\w+(\s*$|\s*\|)|require\s+['"]|attr_accessor|puts\s+|class\s+\w+\s*<\s*\w+|\bend\b/.test(code)) scores.ruby += 3;
  if (/Rails\.|ActiveRecord|params\[|\brender\s+|before_action|has_many/.test(code)) scores.ruby += 3;
  if (/using\s+System|namespace\s+\w+|Console\.(Write|Read)|var\s+\w+\s*=\s*new/.test(code)) scores.csharp += 3;
  if (/\[HttpGet\]|\[HttpPost\]|IActionResult|DbContext|SqlConnection|HttpContext/.test(code)) scores.csharp += 3;
  if (/#include\s*<|int\s+main\s*\(|printf\s*\(|scanf\s*\(|malloc\s*\(|free\s*\(/.test(code)) scores.cpp += 3;
  if (/std::|cout\s*<<|cin\s*>>|#define\s+\w+|nullptr|template\s*</.test(code)) scores.cpp += 3;
  if (/fn\s+\w+\s*\(|let\s+mut\s+|use\s+std::|impl\s+\w+|pub\s+fn|match\s+\w+\s*\{/.test(code)) scores.rust += 4;
  if (/println!\s*\(|Vec::|HashMap::|Option<|Result<|#\[derive/.test(code)) scores.rust += 3;
  if (/^#!.*\/(bash|sh|zsh)|^\s*(if|for|while)\s+.*;\s*then|echo\s+["']|export\s+\w+=/.test(code)) scores.shell += 4;
  if (/\$\{\w+\}|\$\(\(|\beval\s+|\bsed\s+|\bawk\s+|\bcurl\s+/.test(code)) scores.shell += 3;

  var best = 'generic', bestScore = 0;
  Object.keys(scores).forEach(function(lang) { if (scores[lang] > bestScore) { bestScore = scores[lang]; best = lang; } });
  if (scores.typescript >= 3 && scores.typescript >= scores.js) best = 'typescript';
  return best;
}

/* ══════════════════════════════════════════
   SHARED SECRET / CREDENTIAL RULES
══════════════════════════════════════════ */

var RULES = [
  {id:'hardcoded-api-key',  name:'Hardcoded API key',              pat:/["']?(?:api[_-]?key|apiKey|API_KEY|x-api-key)["']?\s*[=:]\s*["']([A-Za-z0-9\-_]{20,})["']/gi, sev:'critical', type:'SECRET', enabled:true},
  {id:'stripe-live-key',    name:'Stripe live secret key',         pat:/sk_live_[A-Za-z0-9]{16,}/g,                 sev:'critical', type:'SECRET', enabled:true},
  {id:'aws-access-key',     name:'AWS access key ID',              pat:/AKIA[0-9A-Z]{16}/g,                         sev:'critical', type:'SECRET', enabled:true},
  {id:'aws-secret-key',     name:'AWS secret access key',          pat:/(?:aws_secret|AWS_SECRET)[_-]?(?:access)?[_-]?key\s*[=:]\s*["']([A-Za-z0-9\/+]{40})["']/gi, sev:'critical', type:'SECRET', enabled:true},
  {id:'slack-token',        name:'Slack bot token',                pat:/xoxb-[0-9A-Za-z\-]{30,}/g,                 sev:'critical', type:'SECRET', enabled:true},
  {id:'slack-webhook',      name:'Slack webhook URL',              pat:/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, sev:'high', type:'SECRET', enabled:true},
  {id:'github-pat',         name:'GitHub personal access token',   pat:/ghp_[A-Za-z0-9]{36}/g,                     sev:'critical', type:'SECRET', enabled:true},
  {id:'github-oauth',       name:'GitHub OAuth token',             pat:/gho_[A-Za-z0-9]{36}/g,                     sev:'critical', type:'SECRET', enabled:true},
  {id:'jwt-secret',         name:'JWT secret hardcoded',           pat:/["']?jwt[_-]?secret["']?\s*[=:]\s*["']([^"']{8,})["']/gi, sev:'critical', type:'SECRET', enabled:true},
  {id:'jwt-token',          name:'JWT token in source',            pat:/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, sev:'high', type:'SECRET', enabled:true},
  {id:'google-api',         name:'Google API key',                 pat:/AIza[0-9A-Za-z\-_]{35}/g,                  sev:'critical', type:'SECRET', enabled:true},
  {id:'twilio-sid',         name:'Twilio account SID',             pat:/AC[a-z0-9]{32}/g,                          sev:'high',     type:'SECRET', enabled:true},
  {id:'sendgrid-key',       name:'SendGrid API key',               pat:/SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43}/g, sev:'critical', type:'SECRET', enabled:true},
  {id:'private-key-block',  name:'Private key in source',          pat:/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, sev:'critical', type:'SECRET', enabled:true},
  {id:'db-conn-string',     name:'MongoDB connection string',      pat:/mongodb(\+srv)?:\/\/[^"'\s]{10,}/g,        sev:'critical', type:'SECRET', enabled:true},
  {id:'postgres-conn',      name:'PostgreSQL connection string',   pat:/postgres(?:ql)?:\/\/[^"'\s]{10,}/g,       sev:'critical', type:'SECRET', enabled:true},
  {id:'mysql-conn',         name:'MySQL connection string',        pat:/mysql:\/\/[^"'\s]{10,}/g,                 sev:'critical', type:'SECRET', enabled:true},
  {id:'redis-conn',         name:'Redis connection string',        pat:/redis:\/\/[^"'\s]{10,}/g,                 sev:'high',     type:'SECRET', enabled:true},
  {id:'mailgun-key',        name:'Mailgun API key',                pat:/key-[0-9a-zA-Z]{32}/g,                    sev:'critical', type:'SECRET', enabled:true},
  {id:'discord-token',      name:'Discord bot token',              pat:/[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g, sev:'critical', type:'SECRET', enabled:true},
  {id:'azure-key',          name:'Azure storage key',              pat:/AccountKey=[A-Za-z0-9+\/]{88}==/g,        sev:'critical', type:'SECRET', enabled:true},
  {id:'gcp-service-acct',   name:'GCP service account key',        pat:/"type"\s*:\s*"service_account"/g,         sev:'critical', type:'SECRET', enabled:true},
];

var CRED_PATTERNS = [
  {id:'hardcoded-password', pat:/["']?(?:password|passwd|pwd|pass|secret)["']?\s*[=:]\s*["']([^"'${}()\s]{6,})["']/gi, name:'Hardcoded password', sev:'critical'},
  {id:'hardcoded-username', pat:/["']?(?:username|user|login)["']?\s*[=:]\s*["']([a-zA-Z0-9._@+\-]{4,})["']/gi, name:'Hardcoded username', sev:'high'},
  {id:'bearer-token',       pat:/Authorization\s*:\s*["']?Bearer\s+([A-Za-z0-9\-._~+\/=]{20,})["']?/gi, name:'Bearer token hardcoded', sev:'critical'},
  {id:'basic-auth',         pat:/Authorization\s*:\s*["']?Basic\s+([A-Za-z0-9+\/=]{10,})["']?/gi, name:'Basic auth hardcoded', sev:'critical'},
];

var MALICIOUS_PKGS = ['flatmap-stream','event-stream','ua-parser-js','colors','coa','rc','node-ipc','peacenotwar','crossenv','cross-env.js','discordjs-selfbot-v13'];

/* ══════════════════════════════════════════
   PATTERN SETS PER LANGUAGE
══════════════════════════════════════════ */

// PYTHON
var PY_SQL = [
  // Direct f-string inside execute()
  {re:/(?:cursor|conn|db|session|c|cur)\s*\.\s*execute\s*\(\s*f["'][^"']*\{/gi, title:'SQL Injection — f-string in execute()', sev:'critical', desc:'f-string SQL interpolation is injectable.', fix:'cursor.execute("SELECT * FROM t WHERE id = ?", (id,))'},
  // f-string SQL assigned to a variable first, then passed to execute()
  {re:/(?:query|sql|stmt|statement)\s*=\s*f["'][^"'\n]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^"'\n]*\{/gi, title:'SQL Injection — f-string SQL query variable', sev:'critical', desc:'SQL query built with f-string interpolation → injectable when passed to execute().', fix:'cursor.execute("SELECT * FROM users WHERE username=?", (username,))'},
  // execute(query) — variable passed directly (two-step pattern)
  {re:/(?:cursor|conn|db|session|c|cur)\s*\.\s*execute\s*\(\s*(?:query|sql|stmt|statement)\s*\)/gi, title:'SQL Injection — variable passed directly to execute()', sev:'high', desc:'A pre-built variable is passed to execute(). If assembled via f-string or concatenation, this is injectable.', fix:'Always use parameterized queries: cursor.execute("SELECT ... WHERE id=?", (val,))'},
  // .format() in execute
  {re:/(?:cursor|conn|db|c|cur)\s*\.\s*execute\s*\([^)]*\.format\s*\(/gi, title:'SQL Injection — .format() in execute()', sev:'critical', desc:'.format() in SQL is injectable.', fix:'Use parameterized queries.'},
  // % formatting in execute
  {re:/(?:cursor|conn|db|c|cur)\s*\.\s*execute\s*\(\s*["'][^"']*["']\s*%\s*/gi, title:'SQL Injection — % formatting in execute()', sev:'critical', desc:'% formatting in SQL is injectable.', fix:'cursor.execute("SELECT * FROM t WHERE id = ?", (val,))'},
  // string concat in execute
  {re:/(?:cursor|conn|db|session|c|cur)\s*\.\s*execute\s*\(\s*["'][^"']*["']\s*\+/gi, title:'SQL Injection — string concatenation in execute()', sev:'critical', desc:'String concatenation in SQL query → injectable.', fix:'Use parameterized queries with ? placeholders.'},
];
var PY_CMD = [
  {re:/os\.system\s*\(\s*(?:f["']|[^"')]*\+)/gi, title:'Command Injection — os.system() dynamic', sev:'critical', desc:'os.system() with user input → OS command execution.', fix:'subprocess.run(["cmd", arg], shell=False)'},
  {re:/subprocess\s*\.\s*(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/gi, title:'Command Injection — subprocess shell=True', sev:'high', desc:'shell=True enables shell metacharacter injection.', fix:'subprocess.run(["cmd", arg], shell=False)'},
  {re:/os\.popen\s*\(\s*(?:f["']|[^"')]*\+)/gi, title:'Command Injection — os.popen() dynamic', sev:'critical', desc:'os.popen() with user input → command injection.', fix:'subprocess.run(["cmd", arg], capture_output=True)'},
  {re:/\beval\s*\(\s*(?:request\.|input\s*\(|os\.environ)/gi, title:'Code Injection — eval() external input', sev:'critical', desc:'eval() on user data = Remote Code Execution.', fix:'Never eval() user input.'},
  {re:/\bexec\s*\(\s*(?:request\.|input\s*\(|os\.environ)/gi, title:'Code Injection — exec() external input', sev:'critical', desc:'exec() on user data = Remote Code Execution.', fix:'Remove exec() on user input.'},
];
var PY_SSTI = [
  {re:/render_template_string\s*\(\s*(?:request\.[^\s,)]+|[^"'\)]*\+\s*(?:request|user_input|data|msg|q))/gi, title:'SSTI — render_template_string() user data', sev:'critical', desc:'User data as Jinja2 template → RCE.', fix:'render_template_string("<div>{{ q }}</div>", q=user_input)'},
  {re:/jinja2\.Template\s*\(\s*(?:request\.|f["'][^"']*\{[^}]*request|[^"'\)]*\+)/gi, title:'SSTI — Jinja2 Template() from user input', sev:'critical', desc:'Jinja2 template from user input → SSTI/RCE.', fix:'Use env.get_template() with file-based templates.'},
];
var PY_DESERIAL = [
  {re:/pickle\.loads?\s*\(\s*(?:request\.|data|user_input|body|payload)/gi, title:'Insecure Deserialization — pickle.load()', sev:'critical', desc:'pickle on untrusted data = arbitrary RCE.', fix:'import json\ndata = json.loads(request.data)'},
  {re:/yaml\.load\s*\(\s*[^,)]+\)/gi, title:'Insecure Deserialization — yaml.load() unsafe', sev:'critical', desc:'yaml.load() without SafeLoader executes arbitrary Python.', fix:'yaml.safe_load(data)'},
  {re:/marshal\.loads?\s*\(\s*(?:request\.|data|user_input|body)/gi, title:'Insecure Deserialization — marshal.loads()', sev:'critical', desc:'marshal of untrusted data → RCE.', fix:'Use JSON for data interchange.'},
  {re:/jsonpickle\.decode\s*\(/gi, title:'Insecure Deserialization — jsonpickle.decode()', sev:'critical', desc:'jsonpickle.decode() can execute arbitrary code.', fix:'Use json.loads() for untrusted inputs.'},
];
var PY_PATH = [
  {re:/open\s*\(\s*(?:request\.\w+\.get\s*\(|f["'][^"']*\{[^}]*(?:request|filename|path))/gi, title:'Path Traversal — open() with request input', sev:'critical', desc:'open() with unvalidated params → read arbitrary files.', fix:'path = os.path.join(base, os.path.basename(input))\nif not path.startswith(base): abort(403)'},
  {re:/send_file\s*\(\s*(?:request\.|os\.path\.join\s*\([^)]*request)/gi, title:'Path Traversal — send_file() with request input', sev:'critical', desc:'Flask send_file() with user path → file disclosure.', fix:'Use werkzeug.utils.safe_join()'},
  // f.save() with unvalidated filename — suppress if secure_filename() is used nearby
  {re:/\.save\s*\(\s*(?:os\.path\.join\s*\([^)]*(?:f\.filename|file\.filename|filename)|filename|path)\s*\)/gi, title:'Path Traversal — file.save() with unvalidated filename', sev:'critical', desc:'Saving an uploaded file using the raw f.filename allows path traversal (e.g. ../../etc/passwd).', fix:'from werkzeug.utils import secure_filename\nfilename = secure_filename(f.filename)\npath = os.path.join("uploads", filename)\nf.save(path)'},
  // os.path.join with raw filename — suppress if secure_filename used nearby
  {re:/os\.path\.join\s*\([^)]*(?:f\.filename|file\.filename|request\.files[^)]*\.filename)\s*\)/gi, title:'Path Traversal — os.path.join() with raw uploaded filename', sev:'critical', desc:'os.path.join() with an unvalidated filename from the request allows directory traversal.', fix:'from werkzeug.utils import secure_filename\nfilename = secure_filename(request.files["file"].filename)'},
];
var PY_SSRF = [
  // User-controlled URL passed to requests
  {re:/requests\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*(?:request\.\w+\.get|request\.args\.get|f["'][^"']*\{[^}]*request)/gi, title:'SSRF — requests library user-controlled URL', sev:'critical', desc:'HTTP to user URL → SSRF, internal network access.', fix:'ALLOWED = ["api.example.com"]\nif urlparse(url).hostname not in ALLOWED: abort(400)'},
  // Hardcoded internal/localhost URL
  {re:/requests\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["']https?:\/\/(?:localhost|127\.0\.0\.1|internal\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/gi, title:'SSRF — requests to hardcoded internal/localhost URL', sev:'high', desc:'HTTP request targeting an internal network address. This can expose internal services to exploitation if the URL is ever influenced by external input.', fix:'Avoid internal URLs in application code. Use service mesh or environment-injected config.'},
  // requests without timeout — DoS risk
  {re:/requests\s*\.\s*(?:get|post|put|delete|patch)\s*\([^)]*\)(?!\s*#[^\n]*timeout)(?![^)]*timeout\s*=)/gi, title:'Missing timeout on requests call — DoS risk', sev:'medium', desc:'requests without a timeout will hang indefinitely if the remote server is slow or unresponsive, causing thread exhaustion.', fix:'requests.get(url, timeout=5)'},
  {re:/urllib\s*\.\s*request\s*\.\s*urlopen\s*\(\s*(?:request\.\w+|f["'][^"']*\{[^}]*request)/gi, title:'SSRF — urllib.urlopen() user-controlled URL', sev:'critical', desc:'urlopen() with unvalidated URL → SSRF.', fix:'Validate and allowlist target URLs.'},
];
var PY_CONFIG = [
  {re:/app\.run\s*\([^)]*debug\s*=\s*True/gi, title:'Flask debug=True (RCE in production)', sev:'critical', desc:'Flask debug=True exposes a Python shell to visitors.', fix:'app.run(debug=os.getenv("FLASK_DEBUG","false")=="true")'},
  {re:/SECRET_KEY\s*=\s*["'][^"']{0,20}["']/gi, title:'Weak/hardcoded Flask SECRET_KEY', sev:'critical', desc:'Short SECRET_KEY allows session cookie forgery.', fix:'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]'},
  {re:/WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False/gi, title:'CSRF protection disabled', sev:'high', desc:'Disabling CSRF allows cross-site request forgery.', fix:'Do not disable CSRF in production.'},
  {re:/verify\s*=\s*False\b/gi, title:'SSL certificate verification disabled', sev:'critical', desc:'verify=False disables TLS validation → MITM.', fix:'Always use verify=True.'},
  {re:/ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/gi, title:'Django ALLOWED_HOSTS wildcard (*)', sev:'high', desc:'ALLOWED_HOSTS = ["*"] allows host header attacks.', fix:'ALLOWED_HOSTS = ["yourdomain.com"]'},
  {re:/DEBUG\s*=\s*True\b/gi, title:'Django DEBUG=True in production', sev:'critical', desc:'Django DEBUG=True exposes stack traces and settings.', fix:'DEBUG = bool(os.environ.get("DJANGO_DEBUG", False))'},
  // os.environ leaked via Flask response
  {re:/(?:jsonify|json\.dumps|return)\s*\(\s*dict\s*\(\s*os\.environ\s*\)|os\.environ\s*\)/gi, title:'Environment variables exposed in HTTP response', sev:'critical', desc:'All environment variables (including secrets, API keys, DB passwords) are returned to the caller. This is a full secret dump.', fix:'# Remove this endpoint entirely, or return only safe non-secret values\nreturn jsonify({"version": os.getenv("APP_VERSION", "unknown")})'},
  // Exception message returned directly to user
  {re:/(?:jsonify|json\.dumps)\s*\(\s*\{[^}]*(?:str\s*\(\s*e\s*\)|str\s*\(\s*err\s*\)|str\s*\(\s*error\s*\)|traceback)[^}]*\}\s*\)/gi, title:'Stack trace / exception detail exposed to user', sev:'high', desc:'Returning raw exception messages leaks internal implementation details, file paths, and variable names to attackers.', fix:'return jsonify({"error": "An internal error occurred"}), 500'},
];
var PY_CRYPTO = [
  {re:/hashlib\.md5\s*\(/gi, title:'Weak hashing — MD5', sev:'high', desc:'MD5 is broken for security use.', fix:'hashlib.sha256(data).hexdigest()'},
  {re:/hashlib\.sha1\s*\(/gi, title:'Weak hashing — SHA-1', sev:'high', desc:'SHA-1 is deprecated.', fix:'hashlib.sha256(data).hexdigest()'},
  {re:/\brandom\.(?:random|randint|choice|shuffle|randrange)\s*\(/gi, title:'Insecure randomness — random module', sev:'high', desc:'random is not cryptographically secure.', fix:'import secrets\nsecrets.token_hex(32)'},
  // base64 used as encryption / token generation
  {re:/base64\.b64encode\s*\(\s*(?:[^)]*\+[^)]*\)|.*(?:password|secret|key|token|user)[^)]*\))/gi, title:'Weak crypto — base64 used as encryption', sev:'critical', desc:'base64 is encoding, not encryption — trivially reversible by anyone. Never use it to "encrypt" sensitive data or tokens.', fix:'from cryptography.fernet import Fernet\nkey = Fernet.generate_key()\nf = Fernet(key)\ntoken = f.encrypt(data.encode())'},
  // Hardcoded crypto secret concatenated into data
  {re:/base64\.b64encode\s*\([^)]*(?:CRYPTO_SECRET|SECRET|secret_key|secret)\s*\)/gi, title:'Weak crypto — hardcoded secret concatenated into base64 token', sev:'critical', desc:'Concatenating a hardcoded secret into base64 is not encryption. The secret is in source code and base64 is trivially reversible.', fix:'Use HMAC or Fernet symmetric encryption with a key stored in environment variables.'},
  // hashlib used for password hashing (not a password-hashing function)
  {re:/hashlib\.(?:md5|sha1|sha256|sha512)\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi, title:'Insecure password hashing — hashlib (not a KDF)', sev:'critical', desc:'hashlib hash functions are too fast for password hashing — easily brute-forced. Use a proper key derivation function.', fix:'import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n# or: from werkzeug.security import generate_password_hash'},
];
var PY_XSS = [
  {re:/return\s+(?:f["'][^"']*<[^>]+>[^"']*\{[^}]*(?:request\.\w+\.get|q\b|name\b|msg\b|user_input))/gi, title:'XSS — Unescaped user input in HTML f-string', sev:'high', desc:'User input in HTML without escaping → reflected XSS.', fix:'from html import escape\nreturn f"<div>{escape(user_input)}</div>"'},
];
var PY_REDIRECT = [
  {re:/redirect\s*\(\s*(?:request\.\w+\.get|request\.args\.get|f["'][^"']*\{[^}]*request)/gi, title:'Open Redirect — redirect() user-controlled URL', sev:'high', desc:'Redirecting to user URL → phishing.', fix:'Validate redirect target is an internal safe URL.'},
];

// PHP
var PHP_SQL = [
  {re:/mysql_query\s*\(\s*["'].*["']\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, title:'SQL Injection — mysql_query() + superglobal', sev:'critical', desc:'Direct superglobal in SQL → injection.', fix:'Use PDO prepared statements.'},
  {re:/mysqli_query\s*\(\s*\$\w+\s*,\s*["'][^"']*["']\s*\.\s*\$/gi, title:'SQL Injection — mysqli_query() string concat', sev:'critical', desc:'String concat in mysqli_query → injectable.', fix:'$stmt = $mysqli->prepare("SELECT * FROM t WHERE id = ?");'},
  {re:/\$(?:pdo|db)\s*->\s*query\s*\(\s*["'].*["']\s*\.\s*\$/gi, title:'SQL Injection — PDO query() string concat', sev:'critical', desc:'PDO query() with concat → injectable.', fix:'$stmt = $pdo->prepare("SELECT * FROM t WHERE id = ?");'},
];
var PHP_CMD = [
  {re:/\bsystem\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, title:'Command Injection — system() + superglobal', sev:'critical', desc:'Superglobal in system() → RCE.', fix:'Validate and whitelist allowed commands.'},
  {re:/\bexec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, title:'Command Injection — exec() + superglobal', sev:'critical', desc:'exec() with user input → RCE.', fix:'Use escapeshellarg() or avoid user input in exec.'},
  {re:/\bpassthru\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, title:'Command Injection — passthru() + superglobal', sev:'critical', desc:'passthru() with user input → RCE.', fix:'Never pass superglobals to shell functions.'},
  {re:/\bshell_exec\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, title:'Command Injection — shell_exec() + user input', sev:'critical', desc:'shell_exec() with user input → RCE.', fix:'Whitelist commands, validate all inputs.'},
  {re:/\beval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, title:'Code Injection — eval() + superglobal', sev:'critical', desc:'eval() on user PHP data = RCE.', fix:'Never eval() user input.'},
  {re:/\bpreg_replace\s*\(\s*["'][^"']*e["'][^)]*\$_(?:GET|POST)/gi, title:'Code Injection — preg_replace /e modifier', sev:'critical', desc:'preg_replace /e evaluates replacement as PHP code.', fix:'Use preg_replace_callback() instead.'},
];
var PHP_XSS = [
  {re:/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/gi, title:'XSS — echo superglobal unescaped', sev:'critical', desc:'Echoing superglobal directly → reflected XSS.', fix:'echo htmlspecialchars($_GET["q"], ENT_QUOTES, "UTF-8");'},
  {re:/print\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/gi, title:'XSS — print superglobal unescaped', sev:'critical', desc:'print of user-controlled variable → XSS.', fix:'echo htmlspecialchars($val, ENT_QUOTES, "UTF-8");'},
];
var PHP_FILE = [
  {re:/include\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, title:'LFI/RFI — include() with user input', sev:'critical', desc:'include() with user input → Local/Remote File Inclusion → RCE.', fix:'Whitelist allowed filenames. Never use user input in include().'},
  {re:/require\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, title:'LFI/RFI — require() with user input', sev:'critical', desc:'require() with user input → LFI/RFI.', fix:'Whitelist allowed filenames.'},
  {re:/file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, title:'SSRF/LFI — file_get_contents() user input', sev:'critical', desc:'file_get_contents() with user URL → SSRF or LFI.', fix:'Validate URL against an allowlist of trusted hosts.'},
];
var PHP_DESERIAL = [
  {re:/unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/gi, title:'Insecure Deserialization — unserialize() + user input', sev:'critical', desc:'PHP unserialize() with user data → PHP object injection → RCE.', fix:'Use json_decode(). Never unserialize untrusted data.'},
];
var PHP_CONFIG = [
  {re:/display_errors\s*=\s*(?:on|1|true)/gi, title:'PHP display_errors enabled in production', sev:'high', desc:'display_errors exposes stack traces to users.', fix:'Set display_errors = Off in php.ini for production.'},
  {re:/register_globals\s*=\s*(?:on|1|true)/gi, title:'PHP register_globals enabled (dangerous)', sev:'critical', desc:'register_globals turns GET/POST params into variables → exploitable.', fix:'Set register_globals = Off. Disabled by default in PHP 5.4+.'},
];

// JAVA
var JAVA_SQL = [
  {re:/Statement\s*\.\s*execute(?:Query|Update)?\s*\(\s*["'].*["']\s*\+/gi, title:'SQL Injection — Statement + concatenation', sev:'critical', desc:'String concat in JDBC Statement → SQL injection.', fix:'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\nstmt.setInt(1, id);'},
  {re:/createQuery\s*\(\s*["'][^"']*["']\s*\+/gi, title:'SQL Injection — JPA createQuery() concat', sev:'critical', desc:'Dynamic JPQL with concat → injectable.', fix:'em.createQuery("SELECT e FROM Entity e WHERE e.id = :id").setParameter("id", id)'},
];
var JAVA_CMD = [
  {re:/Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*(?:\w+\s*\+|\breq\.|\brequest\.)/gi, title:'Command Injection — Runtime.exec() dynamic', sev:'critical', desc:'Runtime.exec() with user input → OS command execution.', fix:'Use ProcessBuilder with List<String> argument array.'},
  {re:/ScriptEngine\s*\.\s*eval\s*\(\s*(?:request\.getParameter|req\.getParameter)/gi, title:'Code Injection — ScriptEngine.eval() user input', sev:'critical', desc:'eval() on user-supplied scripts → arbitrary code execution.', fix:'Never evaluate user-controlled scripts.'},
];
var JAVA_XXE = [
  {re:/DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)(?![^;]*setFeature\s*\([^)]*"http:\/\/apache\.org\/xml\/features\/disallow-doctype-decl"[^)]*true)/gi, title:'XXE — DocumentBuilderFactory without DTD protection', sev:'critical', desc:'XML parsing without DOCTYPE disabled → XXE → file read, SSRF.', fix:'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'},
  {re:/SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)(?![^;]*setFeature)/gi, title:'XXE — SAXParserFactory without DTD protection', sev:'critical', desc:'SAXParser without DTD protection → XXE.', fix:'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'},
];
var JAVA_DESERIAL = [
  {re:/ObjectInputStream\s*\(\s*(?:request\.getInputStream|socket\.getInputStream|new\s+FileInputStream)/gi, title:'Insecure Deserialization — ObjectInputStream', sev:'critical', desc:'Java deserialization of untrusted streams → RCE via gadget chains.', fix:'Use JSON or whitelist-based deserialization.'},
];
var JAVA_CRYPTO = [
  {re:/MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']\s*\)/gi, title:'Weak hashing — MD5 or SHA-1 (Java)', sev:'high', desc:'MD5/SHA-1 are broken.', fix:'MessageDigest.getInstance("SHA-256")'},
  {re:/Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|Blowfish|RC4|AES\/ECB)[^"']*["']\s*\)/gi, title:'Broken cipher algorithm (Java)', sev:'critical', desc:'DES/AES-ECB/RC4 are broken or insecure.', fix:'Cipher.getInstance("AES/GCM/NoPadding")'},
  {re:/Math\.random\s*\(\s*\)/g, title:'Math.random() used for security (Java)', sev:'high', desc:'Math.random() is not cryptographically secure.', fix:'SecureRandom random = new SecureRandom();'},
];

// GO
var GO_SQL = [
  {re:/db\.Query\s*\(\s*(?:fmt\.Sprintf|["'][^"']*["']\s*\+)/gi, title:'SQL Injection — db.Query() string formatting', sev:'critical', desc:'fmt.Sprintf in Go DB query → SQL injection.', fix:'rows, err := db.Query("SELECT * FROM t WHERE id = $1", userID)'},
  {re:/db\.Exec\s*\(\s*(?:fmt\.Sprintf|["'][^"']*["']\s*\+)/gi, title:'SQL Injection — db.Exec() string formatting', sev:'critical', desc:'Dynamic query string in db.Exec() → injectable.', fix:'db.Exec("INSERT INTO t (col) VALUES ($1)", value)'},
];
var GO_CMD = [
  {re:/exec\.Command\s*\(\s*(?:"sh"\s*,\s*"-c"|"bash"\s*,\s*"-c")/gi, title:'Command Injection — exec.Command() shell mode', sev:'critical', desc:'exec.Command("sh","-c",input) → shell injection.', fix:'cmd := exec.Command("program", arg1, arg2)'},
];
var GO_CRYPTO = [
  {re:/md5\.New\s*\(\s*\)|md5\.Sum\s*\(/gi, title:'Weak hashing — MD5 (Go)', sev:'high', desc:'MD5 is broken.', fix:'sha256.New() or sha256.Sum256()'},
  {re:/sha1\.New\s*\(\s*\)|sha1\.Sum\s*\(/gi, title:'Weak hashing — SHA-1 (Go)', sev:'high', desc:'SHA-1 is deprecated.', fix:'sha256.New()'},
  {re:/rand\.Intn\s*\(|rand\.Float64\s*\(|rand\.Int\s*\(/g, title:'Insecure randomness — math/rand (Go)', sev:'high', desc:'math/rand is not cryptographically secure.', fix:'import "crypto/rand"\ncrypto/rand.Read(bytes)'},
];
var GO_SSRF = [
  {re:/http\.Get\s*\(\s*(?:r\.FormValue|r\.URL\.Query|fmt\.Sprintf\s*\([^)]*r\.)/gi, title:'SSRF — http.Get() user-controlled URL (Go)', sev:'critical', desc:'HTTP to user URL → SSRF.', fix:'Validate URL against an allowlist before external requests.'},
];

// RUBY
var RUBY_SQL = [
  {re:/where\s*\(\s*["'][^"']*#\{/gi, title:'SQL Injection — ActiveRecord where() interpolation', sev:'critical', desc:'String interpolation in where() → SQL injection.', fix:'User.where("name = ?", params[:name])'},
  {re:/find_by_sql\s*\(\s*["'][^"']*#\{/gi, title:'SQL Injection — find_by_sql() interpolation', sev:'critical', desc:'find_by_sql with interpolation → injectable.', fix:'User.find_by_sql(["SELECT * FROM t WHERE id = ?", id])'},
];
var RUBY_CMD = [
  {re:/`[^`]*#\{[^}]*(?:params|request)\./gi, title:'Command Injection — backtick exec + params', sev:'critical', desc:'Ruby backtick with user params → command injection.', fix:'Use Open3.capture3 with argument array.'},
  {re:/system\s*\(\s*["'][^"']*#\{[^}]*(?:params|request)\./gi, title:'Command Injection — system() interpolation', sev:'critical', desc:'system() with interpolated params → injection.', fix:'system("command", sanitized_arg)'},
  {re:/eval\s*\(\s*(?:params\[|request\.)/gi, title:'Code Injection — eval() user input (Ruby)', sev:'critical', desc:'eval() on user params → arbitrary Ruby execution.', fix:'Never eval() user input.'},
];
var RUBY_XSS = [
  {re:/\.html_safe\s*$/gm, title:'XSS — .html_safe bypasses Rails auto-escaping', sev:'high', desc:'.html_safe disables escaping. Dangerous with user input.', fix:'Use h() or ERB::Util.html_escape() on user strings.'},
  {re:/raw\s*\(\s*(?:params\[|@\w+)/gi, title:'XSS — raw() with user-controlled variable (Rails)', sev:'high', desc:'raw() outputs unescaped HTML. Never use with user input.', fix:'Use default Rails escaping: <%= @variable %>'},
];
var RUBY_DESERIAL = [
  {re:/Marshal\.load\s*\(\s*(?:params|request|Base64\.decode)/gi, title:'Insecure Deserialization — Marshal.load()', sev:'critical', desc:'Marshal.load() with untrusted data → arbitrary code.', fix:'Use JSON.parse() for data interchange.'},
  {re:/YAML\.load\s*\(\s*(?:params|request|File\.read)/gi, title:'Insecure Deserialization — YAML.load() unsafe', sev:'critical', desc:'YAML.load() with user data → arbitrary Ruby via Psych.', fix:'YAML.safe_load(data)'},
];

// C/C++
var CPP_VULNS = [
  {re:/\bgets\s*\(\s*\w+/gi, title:'Buffer Overflow — gets() (no bounds check)', sev:'critical', desc:'gets() has no bounds checking → unconditionally vulnerable to overflow.', fix:'fgets(buf, sizeof(buf), stdin);'},
  {re:/\bstrcpy\s*\(\s*\w+\s*,/gi, title:'Buffer Overflow — strcpy() no bounds check', sev:'critical', desc:'strcpy() does not check buffer length → stack/heap overflow.', fix:'strncpy(dst, src, sizeof(dst) - 1); dst[sizeof(dst)-1] = 0;'},
  {re:/\bsprintf\s*\(\s*\w+\s*,\s*\w+\s*,/gi, title:'Buffer Overflow — sprintf() potential overflow', sev:'high', desc:'sprintf() without bounds check can overflow destination.', fix:'snprintf(buf, sizeof(buf), "%s", src);'},
  {re:/\bscanf\s*\(\s*["']%s["']/gi, title:'Buffer Overflow — scanf("%s") unbounded read', sev:'critical', desc:'scanf %s reads unlimited input → overflow.', fix:'scanf("%255s", buf);'},
  {re:/\bstrcat\s*\(\s*\w+\s*,/gi, title:'Buffer Overflow — strcat() no bounds check', sev:'high', desc:'strcat() does not validate buffer capacity.', fix:'strncat(dst, src, sizeof(dst) - strlen(dst) - 1);'},
  {re:/\bsystem\s*\(\s*\w+/gi, title:'Command Injection — system() with variable', sev:'critical', desc:'system() with variable may enable command injection.', fix:'Use execve() with argv array.'},
  {re:/\bprintf\s*\(\s*\w+\s*\)/gi, title:'Format String Vulnerability — printf(userStr)', sev:'critical', desc:'printf() with user format string → arbitrary read/write.', fix:'printf("%s", user_string);'},
];

// CSHARP
var CS_SQL = [
  {re:/new\s+SqlCommand\s*\(\s*["'][^"']*["']\s*\+\s*\w+/gi, title:'SQL Injection — SqlCommand string concat (C#)', sev:'critical', desc:'String concat in SqlCommand → SQL injection.', fix:'var cmd = new SqlCommand("SELECT * FROM t WHERE id = @id", conn);\ncmd.Parameters.AddWithValue("@id", id);'},
];
var CS_XXE = [
  {re:/new\s+XmlDocument\s*\(\s*\)(?![^;]*\.XmlResolver\s*=\s*null)/gi, title:'XXE — XmlDocument without null XmlResolver (C#)', sev:'critical', desc:'XmlDocument without null resolver → XXE.', fix:'var doc = new XmlDocument();\ndoc.XmlResolver = null;\ndoc.LoadXml(xml);'},
];
var CS_CRYPTO = [
  {re:/MD5\.Create\s*\(\s*\)|new\s+MD5CryptoServiceProvider\s*\(\s*\)/gi, title:'Weak hashing — MD5 (C#)', sev:'high', desc:'MD5 is broken.', fix:'SHA256.Create()'},
  {re:/SHA1\.Create\s*\(\s*\)|new\s+SHA1CryptoServiceProvider\s*\(\s*\)/gi, title:'Weak hashing — SHA-1 (C#)', sev:'high', desc:'SHA-1 is deprecated.', fix:'SHA256.Create()'},
  {re:/DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider/gi, title:'Broken cipher — DES/3DES/RC2 (C#)', sev:'critical', desc:'DES, 3DES, RC2 are broken.', fix:'new AesGcm(key)'},
];

// RUST
var RUST_VULNS = [
  {re:/unsafe\s*\{[^}]*\bptr::/gi, title:'Unsafe Code — raw pointer dereference (Rust)', sev:'high', desc:'Raw pointer ops in unsafe bypass Rust safety.', fix:'Consider safe alternatives. Document safety invariants thoroughly.'},
  {re:/\.unwrap\(\)/g, title:'Error Handling — unwrap() panics on None/Err (Rust)', sev:'medium', desc:'.unwrap() crashes on None/Err → denial of service.', fix:'Use ? operator, match, or .unwrap_or_else(|e| ...).'},
  {re:/from_utf8_unchecked|from_raw_parts\s*\(|std::mem::transmute/gi, title:'Unsafe Memory — unchecked cast (Rust)', sev:'high', desc:'Unchecked memory casts → UB, corruption, RCE.', fix:'Use safe alternatives: from_utf8()?.'},
];

// SHELL
var SHELL_VULNS = [
  {re:/eval\s+["']?\$\{?\w+\}?/gi, title:'Code Injection — eval with variable (Shell)', sev:'critical', desc:'eval of variable → arbitrary code execution.', fix:'Never eval untrusted input.'},
  {re:/curl\s+[^|]*\|\s*(?:bash|sh)/gi, title:'RCE — curl pipe to shell', sev:'critical', desc:'curl | bash downloads and executes untrusted code.', fix:'Download first, verify checksum, then execute.'},
  {re:/wget\s+[^|]*\|\s*(?:bash|sh)/gi, title:'RCE — wget pipe to shell', sev:'critical', desc:'wget | bash executes untrusted remote code.', fix:'Download to file, verify checksum first.'},
  {re:/chmod\s+777\s+/gi, title:'Misconfiguration — chmod 777 (world-writable)', sev:'high', desc:'chmod 777 → world-writable files, any user can modify.', fix:'chmod 755 dirs, 644 files, 600 secrets.'},
  {re:/rm\s+-rf?\s+\$/gi, title:'Destructive — rm -rf with variable path', sev:'critical', desc:'rm -rf with variable path → accidental full deletion.', fix:'[ -n "$DIR" ] && rm -rf "$DIR"'},
  {re:/\bpassword\s*=\s*["'][^"']+["']/gi, title:'Hardcoded password in shell script', sev:'critical', desc:'Passwords in shell scripts appear in history and process lists.', fix:'PASSWORD=$DB_PASSWORD  # Use environment variables'},
];

/* ══════════════════════════════════════════
   MODULE INFO
══════════════════════════════════════════ */

var MOD_INFO = [
  {name:'Secret Detection',          type:'SECRET',  det:'22+ patterns across all languages',              desc:'Hardcoded API keys, tokens, connection strings.',isNew:false},
  {name:'Credential Extraction',     type:'CRED',    det:'Password, username, Basic/Bearer auth',          desc:'Hardcoded credentials and auth headers.',isNew:false},
  {name:'Endpoint Discovery',        type:'ENDPOINT',det:'Admin, debug, internal, sensitive file paths',   desc:'Exposes undocumented routes and admin panels.',isNew:false},
  {name:'XSS / SSTI Detection',      type:'XSS',     det:'JS DOM, PHP echo, Rails raw(), Python SSTI',    desc:'Traces user data to dangerous rendering sinks.',isNew:false},
  {name:'Prototype Pollution',       type:'PROTO',   det:'Recursive merge, jQuery extend, Object.assign',  desc:'Unsafe object merge patterns (JS/TS).',isNew:false},
  {name:'Weak Cryptography',         type:'CRYPTO',  det:'MD5, SHA-1, DES, ECB, Math.random — all langs', desc:'Broken hash and cipher algorithms.',isNew:false},
  {name:'Supply Chain Scanner',      type:'SUPPLY',  det:'Known malicious packages + suspicious CDNs',    desc:'Cross-references against compromised packages.',isNew:false},
  {name:'Logic Flaw Analysis',       type:'LOGIC',   det:'Auth bypasses, open redirects, CSRF',           desc:'Authorization and business logic flaws.',isNew:false},
  {name:'Config Analyzer',           type:'CONFIG',  det:'Debug flags, CORS, SSL, PHP/Flask/Django',      desc:'Insecure configuration across frameworks.',isNew:false},
  {name:'Injection Detection',       type:'INJECT',  det:'SQL, command, code, SSTI — all 10 languages',  desc:'Unsanitized input in dangerous sinks.',isNew:false},
  {name:'Insecure Storage',          type:'STORAGE', det:'localStorage, sessionStorage, cookies',         desc:'Sensitive data stored insecurely (JS).',isNew:false},
  {name:'Insecure Deserialization',  type:'DESERIAL', det:'pickle, yaml.load, unserialize, ObjectInputStream, Marshal', desc:'Deserialization across Python/PHP/Java/Ruby.',isNew:false},
  {name:'Path Traversal',            type:'PATH',    det:'open(), send_file(), file_get_contents(), include()', desc:'File operations with unvalidated user input.',isNew:false},
  {name:'SSRF Detection',            type:'SSRF',    det:'requests, urllib, http.Get, file_get_contents', desc:'Server-side request forgery.',isNew:false},
  {name:'XXE Detection',             type:'XXE',     det:'DocumentBuilderFactory, SAXParser, XmlDocument', desc:'XML External Entity (Java, C#).',isNew:true},
  {name:'Buffer Overflow (C/C++)',   type:'BUFFER',  det:'gets(), strcpy(), sprintf(), scanf, printf(var)', desc:'Unsafe C/C++ functions → overflows.',isNew:true},
  {name:'Shell Injection',           type:'SHELL',   det:'eval $var, curl|bash, chmod 777, hardcoded pw', desc:'Dangerous shell patterns and script misconfig.',isNew:true},
  {name:'PHP Security Scanner',      type:'PHP',     det:'$_GET/$_POST in SQL/exec/eval/include/echo',   desc:'Full PHP superglobal taint tracking.',isNew:true},
  {name:'Java Security Analyzer',    type:'JAVA',    det:'JDBC inject, ObjectInputStream, ScriptEngine', desc:'Java-specific vulnerability detection.',isNew:true},
  {name:'Go Security Analyzer',      type:'GO',      det:'db.Query Sprintf, exec.Command sh -c, math/rand', desc:'Go SQL injection, cmd injection, crypto.',isNew:true},
  {name:'Ruby Security Analyzer',    type:'RUBY',    det:'where() interpolation, html_safe, Marshal.load', desc:'Rails/Ruby vulnerability detection.',isNew:true},
  {name:'C# Security Analyzer',      type:'CSHARP',  det:'SqlCommand concat, XmlDocument XXE, weak crypto', desc:'ASP.NET/C# security issue detection.',isNew:true},
  {name:'Rust Safety Analyzer',      type:'RUST',    det:'unsafe blocks, .unwrap(), transmute',           desc:'Rust unsafe code and error handling issues.',isNew:true},
];

/* ══════════════════════════════════════════
   HELPERS
══════════════════════════════════════════ */

function lineOf(code, idx) { return code.slice(0, idx).split('\n').length; }
function snip(code, ln)    { return (code.split('\n')[ln - 1] || '').trim().slice(0, 160); }

function runPats(code, patterns, typeId, baseId, extraFields) {
  var F = [], lines = code.split('\n');
  patterns.forEach(function(p) {
    var re = new RegExp(p.re.source, p.re.flags), m;
    while ((m = re.exec(code)) !== null) {
      var ln = lineOf(code, m.index);
      var f = {
        id: baseId + '-' + ln, type: typeId, title: p.title, sev: p.sev,
        loc: 'line ' + ln, line: ln,
        snippet: lines[ln-1] ? lines[ln-1].trim() : m[0].slice(0, 100),
        match: m[0].slice(0, 100), desc: p.desc,
        remediation: { text: p.desc, fix: p.fix },
        confidence: p.confidence || 88, taint: p.taint || null,
      };
      if (extraFields) Object.keys(extraFields).forEach(function(k) { f[k] = extraFields[k]; });
      F.push(f);
    }
  });
  return F;
}

/* ══════════════════════════════════════════
   CORE DETECTORS
══════════════════════════════════════════ */

function detectSecrets(code) {
  var F = [];
  RULES.filter(function(r) { return r.enabled && r.type === 'SECRET'; }).forEach(function(rule) {
    var re = new RegExp(rule.pat.source, rule.pat.flags), m;
    while ((m = re.exec(code)) !== null) {
      var ln = lineOf(code, m.index);
      F.push({ id: rule.id, type: 'SECRET', title: rule.name, sev: rule.sev, loc: 'line ' + ln, line: ln, snippet: snip(code, ln), match: m[0].slice(0, 80), desc: 'Hardcoded ' + rule.name.toLowerCase() + ' found in source.', remediation: { text: 'Store in environment variables or a secrets manager.', fix: 'const KEY = process.env.SECRET_KEY; // or os.environ["SECRET_KEY"]' }, confidence: 92, taint: null });
    }
  });
  return F;
}

function detectCredentials(code) {
  var F = [];
  CRED_PATTERNS.forEach(function(rule) {
    var re = new RegExp(rule.pat.source, rule.pat.flags), m;
    while ((m = re.exec(code)) !== null) {
      var captured = m[1] || m[0];
      if (/process\.env|getenv|\$\{|ENV\[|os\.environ|\$_ENV/.test(captured)) continue;
      if (captured.length < 4 || /^(your|xxx|test|demo|example|placeholder|changeme|replace|password|secret)$/i.test(captured)) continue;
      var ln = lineOf(code, m.index);
      F.push({ id: rule.id + '-' + ln, type: 'CRED', title: rule.name, sev: rule.sev, loc: 'line ' + ln, line: ln, snippet: snip(code, ln), match: m[0].slice(0, 80), desc: 'Hardcoded credential found.', remediation: { text: 'Use environment variables or a vault service.', fix: 'password = os.environ["DB_PASSWORD"]' }, confidence: 88, taint: null });
    }
  });
  return F;
}

function detectEndpoints(code) {
  var F = [];
  [
    {re:/["'`](\/(?:admin|administrator|wp-admin|panel|manage)[\w\-\/?=&]*)/gi,   label:'Admin endpoint',            sev:'high'},
    {re:/["'`](\/(?:debug|test|staging|dev|sandbox)[\w\-\/?=&]*)/gi,             label:'Debug/dev route',           sev:'high'},
    {re:/["'`](\/api\/(?:v\d\/)?(?:private|internal|export|admin)[\w\-\/?=&]*)/gi, label:'Internal API route',      sev:'medium'},
    {re:/["'`](\/.env|\/\.git\/config|\/config\.json|\/secrets\.json|\/\.htpasswd)/gi, label:'Sensitive file path', sev:'critical'},
    {re:/["'`](\/actuator(?:\/[\w\-\/?=&]*)?)/gi,                                label:'Spring actuator endpoint',  sev:'high'},
    {re:/["'`](\/swagger(?:-ui)?(?:\/[\w\-\/?=&]*)?)/gi,                         label:'Swagger docs exposed',      sev:'low'},
    {re:/["'`](\/phpmyadmin(?:\/[\w\-\/?=&]*)?)/gi,                              label:'phpMyAdmin exposed',        sev:'critical'},
    {re:/["'`](\/graphql(?:\/[\w\-\/?=&]*)?)/gi,                                 label:'GraphQL endpoint exposed',  sev:'medium'},
  ].forEach(function(p) {
    var re = new RegExp(p.re.source, p.re.flags), m;
    while ((m = re.exec(code)) !== null) {
      var ln = lineOf(code, m.index);
      F.push({ id: 'endpoint-' + p.label.replace(/\s/g,'-').toLowerCase() + '-' + ln, type:'ENDPOINT', title: p.label + ' exposed', sev: p.sev, loc:'line '+ln, line:ln, snippet:snip(code,ln), match:m[1]||m[0], desc:'Endpoint "' + (m[1]||m[0]) + '" found in source.', remediation:{text:'Verify server-side auth. Remove internal paths from client code.', fix:'// Keep internal routes server-side only'}, confidence:80, taint:null });
    }
  });
  return F;
}

function detectXSS(code) {
  var F = [], lang = detectLanguage(code), lines = code.split('\n');
  // JS/TS DOM XSS
  if (lang==='js'||lang==='typescript'||lang==='generic') {
    if (/location\.(hash|search|href|pathname)|URLSearchParams|document\.referrer|window\.name|params\.get\(/.test(code)) {
      [{re:/innerHTML\s*=/g,sink:'innerHTML',title:'DOM XSS — innerHTML sink'},{re:/outerHTML\s*=/g,sink:'outerHTML',title:'DOM XSS — outerHTML sink'},{re:/document\.write\s*\(/g,sink:'document.write()',title:'DOM XSS — document.write sink'},{re:/\.insertAdjacentHTML\s*\(/g,sink:'insertAdjacentHTML()',title:'DOM XSS — insertAdjacentHTML sink'},{re:/eval\s*\(/g,sink:'eval()',title:'DOM XSS — eval() sink'}].forEach(function(p){
        var re=new RegExp(p.re.source,p.re.flags),m;
        while((m=re.exec(code))!==null){var ln=lineOf(code,m.index);F.push({id:'xss-js-'+p.sink.replace(/[^a-z]/gi,'-')+'-'+ln,type:'XSS',title:p.title,sev:'critical',loc:'line '+ln,line:ln,snippet:lines[ln-1]?lines[ln-1].trim():'',match:m[0],desc:'User-controlled data may reach '+p.sink+' without sanitization.',remediation:{text:'Use DOMPurify or textContent instead.',fix:'el.innerHTML = DOMPurify.sanitize(untrustedInput);'},confidence:90,taint:{source:'location.hash / URLSearchParams',flow:['unsanitized'],sink:p.sink}});}
      });
    }
  }
  // Express reflected XSS: res.send() with template literal expressions or concatenation containing user data
  if(lang==='js'||lang==='typescript'||lang==='generic'){
    var SAFE_ENCODE_FNS = 'he|escape|encodeHTML|escapeHtml|sanitize|DOMPurify|xss|htmlspecialchars|entities';
    var xssExpressPatterns = [
      // res.send(`...${varName}...`) — taint-aware: suppress if varName was assigned from an escape call above
      {
        re: new RegExp('res\\.send\\(\\s*`[^`]*\\$\\{(?!(?:' + SAFE_ENCODE_FNS + ')\\s*[\\.\\(])([a-zA-Z_$][\\w\\.]*)','gi'),
        title: 'Reflected/Stored XSS — res.send() with unescaped template literal expression',
        sev: 'critical',
        desc: 'res.send() renders a template literal with an interpolated variable as raw HTML. If that variable contains user or DB input this is an XSS vulnerability.',
        fix: "const he = require('he');\nres.send(`<div>${he.encode(q)}</div>`);",
        taintCheck: function(matchIndex, captureGroup) {
          if (!captureGroup) return false;
          var before = code.slice(Math.max(0, matchIndex - 400), matchIndex);
          return new RegExp('\\b' + captureGroup + '\\s*=\\s*(?:' + SAFE_ENCODE_FNS + ')[.(]').test(before);
        }
      },
      // res.send('<tag>...' + expr) — flag unescaped concat when HTML tag present in the literal part
      {re:/res\s*\.\s*send\s*\(\s*["']<[^"']*["']\s*\+\s*(?!he\.|escape|encodeHTML|escapeHtml|sanitize|DOMPurify)\w/gi, title:'Reflected XSS — res.send() HTML string concatenated with unescaped value',sev:'critical',desc:'HTML string concatenated with an unescaped variable in res.send() — reflected XSS if the variable contains user or DB data.',fix:"res.send('<div>' + he.encode(userValue) + '</div>');"},
      // html += `<tag>${expr}` — unescaped variable in HTML accumulator
      {re:/html\s*\+=\s*`<[^`]*\$\{(?!(?:he|escape|encodeHTML|escapeHtml|sanitize|DOMPurify)\s*[\.\(])[^}]+\}/gi, title:'Stored XSS — unescaped variable appended to HTML accumulator',sev:'critical',desc:'Variable interpolated into an HTML accumulator string without escaping — classic stored XSS when the value originates from user-supplied database content.',fix:"const he = require('he');\nhtml += `<div>${he.encode(row.msg)}</div>`;"},
    ];
    xssExpressPatterns.forEach(function(p){
      var re=new RegExp(p.re.source,p.re.flags),m;
      while((m=re.exec(code))!==null){
        if(p.taintCheck && p.taintCheck(m.index, m[1])) continue; // skip if already escaped
        var ln=lineOf(code,m.index);
        F.push({id:'xss-express-'+ln,type:'XSS',title:p.title,sev:p.sev,loc:'line '+ln,line:ln,snippet:lines[ln-1]?lines[ln-1].trim():m[0],match:m[0].slice(0,80),desc:p.desc,remediation:{text:'HTML-encode all user-controlled data before inserting into HTML responses. Use `he` or `escape-html`.',fix:p.fix},confidence:88,taint:{source:'req.query / req.body / db row',flow:['unsanitized'],sink:'res.send()'}});
      }
    });
  }
  if (lang==='python'||lang==='generic') { F=F.concat(runPats(code,PY_XSS,'XSS','xss-py',null)); F=F.concat(runPats(code,PY_SSTI,'INJECT','inject-ssti',null)); }
  if (lang==='php'||lang==='generic')    F=F.concat(runPats(code,PHP_XSS,'XSS','xss-php',null));
  if (lang==='ruby'||lang==='generic')   F=F.concat(runPats(code,RUBY_XSS,'XSS','xss-ruby',null));
  return F;
}

function detectProto(code) {
  var F=[], lines=code.split('\n');
  [{re:/for\s*\(\s*(const|let|var)?\s*key\s+in\s+\w+\s*\)(?![^{]*hasOwnProperty)/g,title:'Prototype pollution — unsafe for..in merge',confidence:85},{re:/Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|request\.|user\.)/g,title:'Prototype pollution — Object.assign with user input',confidence:80},{re:/\$\.extend\s*\(\s*true/g,title:'Prototype pollution — jQuery deep extend',confidence:90},{re:/\[["']__proto__["']\]|\.constructor\s*\[["']prototype["']\]/g,title:'Prototype pollution — direct __proto__ access',confidence:95}].forEach(function(p){
    var re=new RegExp(p.re.source,p.re.flags),m;
    while((m=re.exec(code))!==null){var ln=lineOf(code,m.index);F.push({id:'proto-'+ln,type:'PROTO',title:p.title,sev:'critical',loc:'line '+ln,line:ln,snippet:lines[ln-1]?lines[ln-1].trim():m[0],match:m[0].slice(0,60),desc:'Unsafe object merge. Attackers can pollute Object.prototype.',remediation:{text:'Guard dangerous keys.',fix:'const UNSAFE=["__proto__","constructor","prototype"];\nfor(const key of Object.keys(src)){\n  if(UNSAFE.includes(key)) continue;\n  target[key]=src[key];\n}'},confidence:p.confidence,taint:null});}
  });
  return F;
}

function detectSupply(code) {
  var F=[],importRe=/import\s+(?:\w+\s+from\s+)?['"]([^'"]+)['"]/g,requireRe=/require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,cdnRe=/src\s*=\s*["'](https?:\/\/(?!cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|fonts\.googleapis\.com)[^"']+\.js)["']/gi;
  var pkgs=[], m;
  while((m=importRe.exec(code))!==null) pkgs.push({name:m[1],idx:m.index});
  while((m=requireRe.exec(code))!==null) pkgs.push({name:m[1],idx:m.index});
  MALICIOUS_PKGS.forEach(function(pkg){
    var hit=pkgs.find(function(p){return p.name===pkg||p.name.startsWith(pkg+'/');});
    if(hit){var ln=lineOf(code,hit.idx);F.push({id:'supply-'+pkg,type:'SUPPLY',title:'Supply chain risk — '+pkg,sev:'critical',loc:'line '+ln,line:ln,snippet:snip(code,ln),match:pkg,desc:'"'+pkg+'" has a known supply chain compromise.',remediation:{text:'Remove immediately. Run: npm audit --fix',fix:'// npm audit fix && npm ci'},confidence:99,taint:null});}
  });
  var re2=new RegExp(cdnRe.source,cdnRe.flags);
  while((m=re2.exec(code))!==null){var ln=lineOf(code,m.index);F.push({id:'supply-cdn-'+ln,type:'SUPPLY',title:'Unrecognized external CDN script',sev:'medium',loc:'line '+ln,line:ln,snippet:snip(code,ln),match:m[1].slice(0,80),desc:'Script from unrecognized CDN.',remediation:{text:'Self-host or use a trusted SRI-protected CDN.',fix:'<script src="..." integrity="sha384-..." crossorigin="anonymous">'},confidence:70,taint:null});}
  return F;
}

function detectCrypto(code) {
  var F=[], lang=detectLanguage(code);
  if(lang==='js'||lang==='typescript'||lang==='generic'){
    [{re:/createHash\s*\(\s*['"]md5['"]\s*\)/g,title:'MD5 used for hashing',sev:'high',fix:"crypto.createHash('sha256').update(data).digest('hex')"},{re:/createHash\s*\(\s*['"]sha1['"]\s*\)/g,title:'SHA-1 used for hashing',sev:'high',fix:"crypto.createHash('sha256').update(data).digest('hex')"},{re:/Math\.random\s*\(\s*\)/g,title:'Math.random() for security tokens',sev:'high',fix:'crypto.getRandomValues(new Uint8Array(32))'},{re:/rejectUnauthorized\s*:\s*false/gi,title:'TLS certificate verification disabled',sev:'critical',fix:'// Remove rejectUnauthorized: false'},{re:/createCipheriv\s*\(\s*['"](?:des|rc4|aes-\d+-ecb)['"]/gi,title:'Broken cipher algorithm (JS)',sev:'critical',fix:"crypto.createCipheriv('aes-256-gcm', key, iv)"}].forEach(function(p){
      var re=new RegExp(p.re.source,p.re.flags),m;
      while((m=re.exec(code))!==null){var ln=lineOf(code,m.index);F.push({id:'crypto-js-'+ln,type:'CRYPTO',title:p.title,sev:p.sev,loc:'line '+ln,line:ln,snippet:snip(code,ln),match:m[0].slice(0,60),desc:p.title+' detected.',remediation:{text:'Use a modern secure algorithm.',fix:p.fix},confidence:92,taint:null});}
    });
  }
  if(lang==='python'||lang==='generic') F=F.concat(runPats(code,PY_CRYPTO,'CRYPTO','crypto-py',null));
  if(lang==='java'||lang==='generic')   F=F.concat(runPats(code,JAVA_CRYPTO,'CRYPTO','crypto-java',null));
  if(lang==='go'||lang==='generic')     F=F.concat(runPats(code,GO_CRYPTO,'CRYPTO','crypto-go',null));
  if(lang==='csharp'||lang==='generic') F=F.concat(runPats(code,CS_CRYPTO,'CRYPTO','crypto-cs',null));
  return F;
}

function detectLogic(code) {
  var F=[], lang=detectLanguage(code), lines=code.split('\n');
  if(lang==='js'||lang==='typescript'||lang==='generic'){
    [{re:/localStorage\.getItem\s*\(.*\)\s*===\s*['"](?:true|1|admin)['"]/g,title:'Authorization via localStorage (bypassable)',sev:'critical',desc:'Auth via localStorage is trivially bypassable.',fix:'const res = await fetch("/api/auth/check");\nif (!res.ok) redirect("/login");'},{re:/if\s*\(\s*(?:is_?admin|isAdmin|role\s*===\s*['"]admin)\s*\)/g,title:'Client-side admin role check',sev:'high',desc:'Client-side role checks can be bypassed via DevTools.',fix:'// Validate roles server-side only'},{re:/window\.location\.href\s*=\s*(?:params\.get|location\.search|decodeURIComponent)/g,title:'Open Redirect — location.href from params',sev:'high',desc:'Setting location.href from URL params allows phishing.',fix:'const SAFE=["/dashboard","/home"];\nif(SAFE.includes(next)) window.location.href=next;'}].forEach(function(p){
      var re=new RegExp(p.re.source,p.re.flags),m;
      while((m=re.exec(code))!==null){var ln=lineOf(code,m.index);F.push({id:'logic-js-'+ln,type:'LOGIC',title:p.title,sev:p.sev,loc:'line '+ln,line:ln,snippet:lines[ln-1]?lines[ln-1].trim():m[0],match:m[0].slice(0,60),desc:p.desc,remediation:{text:'Move authorization logic server-side.',fix:p.fix},confidence:85,taint:null});}
    });
  }
  if(lang==='python'||lang==='generic') F=F.concat(runPats(code,PY_REDIRECT,'LOGIC','redirect-py',null));
  return F;
}

function detectConfig(code) {
  var F=[], lang=detectLanguage(code);
  [{re:/\bDEBUG\s*=\s*true\b|\bdebug\s*:\s*true\b/gi,title:'Debug mode enabled',sev:'medium'},{re:/console\.(log|debug|info)\s*\(.*(?:password|token|secret|key|auth)/gi,title:'Sensitive data logged to console',sev:'high'},{re:/Access-Control-Allow-Origin['":\s]*\*/gi,title:'CORS wildcard origin (*) allowed',sev:'high'},{re:/secure\s*:\s*false|httpOnly\s*:\s*false/gi,title:'Insecure cookie configuration',sev:'high'},{re:/ssl_verify\s*=\s*False|VERIFY_SSL\s*=\s*False/gi,title:'SSL verification disabled (config flag)',sev:'critical'},{re:/res\s*\.\s*json\s*\(\s*process\.env\s*\)|res\s*\.\s*send\s*\(\s*process\.env\s*\)/gi,title:'Environment variables exposed via HTTP response',sev:'critical'},{re:/Buffer\.from\s*\([^)]*\)\s*\.\s*toString\s*\(\s*['"]base64['"]\s*\)\s*(?:;|,|\))/gi,title:'Weak token — plain base64 encoding (trivially reversible)',sev:'high'},{re:/app\.(get|post|put|delete|patch)\s*\(\s*['"`]\/(?:debug|env|config|secret|internal|admin)['"` ]/gi,title:'Sensitive route exposed without apparent auth middleware',sev:'high'}].forEach(function(p){
    var re=new RegExp(p.re.source,p.re.flags),m;
    while((m=re.exec(code))!==null){var ln=lineOf(code,m.index);F.push({id:'config-'+ln,type:'CONFIG',title:p.title,sev:p.sev,loc:'line '+ln,line:ln,snippet:snip(code,ln),match:m[0].slice(0,60),desc:p.title+' found in source.',remediation:{text:'Fix before production deployment.',fix:'// Remove or disable in production'},confidence:80,taint:null});}
  });
  if(lang==='python'||lang==='generic') F=F.concat(runPats(code,PY_CONFIG,'CONFIG','config-py',null));
  if(lang==='php'   ||lang==='generic') F=F.concat(runPats(code,PHP_CONFIG,'CONFIG','config-php',null));
  return F;
}

<<<<<<< HEAD
function detectInjection(code) {
  var F=[], lang=detectLanguage(code), lines=code.split('\n');
  if(lang==='js'||lang==='typescript'||lang==='generic'){
    [{re:/["'`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\s[^"'`]*["'`]\s*\+/gi,title:'SQL injection — string concatenation (JS)',sev:'critical',desc:'SQL query built with string concatenation — user input can break out of the query structure.',fix:"db.query('SELECT * FROM users WHERE id = ?', [userId])"},{re:/(?:db|pool|connection|conn|client)\s*\.\s*(?:query|get|run|all|exec|execute)\s*\(\s*(?:query|sql|str|q)\s*[,)]/gi,title:'SQL injection — variable passed directly to db call (JS)',sev:'critical',desc:'A variable (likely assembled via concatenation) is passed directly to a database call without parameterization.',fix:"db.query('SELECT * FROM t WHERE id = ?', [id])"},{re:/exec\s*\(\s*["'`].*\+|execSync\s*\([^)]*\+/g,title:'Command injection — dynamic exec (JS)',sev:'critical',desc:'User input may reach shell exec.',fix:"spawn('cmd', [arg1, arg2], { shell: false })"}].forEach(function(p){
      var re=new RegExp(p.re.source,p.re.flags),m;
      while((m=re.exec(code))!==null){var ln=lineOf(code,m.index);F.push({id:'inject-js-'+ln,type:'INJECT',title:p.title,sev:p.sev,loc:'line '+ln,line:ln,snippet:lines[ln-1]?lines[ln-1].trim():m[0],match:m[0].slice(0,80),desc:p.desc,remediation:{text:'Use parameterized queries or safe APIs.',fix:p.fix},confidence:88,taint:{source:'user-controlled input',flow:['unsanitized'],sink:p.title}});}
    });
  }
  if(lang==='python'||lang==='generic'){
    // Extra pass: catch cur.execute(f"...{var}...") directly — the base PY_SQL pattern covers the variable case
    var pyDirectFRe = /(?:cursor|conn|db|session|c|cur)\s*\.\s*execute\s*\(\s*f["'][^"'\n]*\{[^}]*\}/gi;
    var m2;
    while((m2=pyDirectFRe.exec(code))!==null){
      var ln2=lineOf(code,m2.index);
      F.push({id:'inject-py-sql-direct-'+ln2,type:'INJECT',title:'SQL Injection — f-string directly in execute()',sev:'critical',loc:'line '+ln2,line:ln2,snippet:lines[ln2-1]?lines[ln2-1].trim():m2[0],match:m2[0].slice(0,100),desc:'f-string interpolation inside execute() call — user-controlled variables interpolated into SQL are injectable.',remediation:{text:'Use parameterized queries.',fix:'cur.execute("SELECT * FROM users WHERE username=?", (username,))'},confidence:95,taint:{source:'function argument / request data',flow:['f-string interpolation'],sink:'execute()'}});
    }
    F=F.concat(runPats(code,PY_SQL,'INJECT','inject-py-sql',null)); F=F.concat(runPats(code,PY_CMD,'INJECT','inject-py-cmd',null));
  }
  if(lang==='php'||lang==='generic'){    F=F.concat(runPats(code,PHP_SQL,'INJECT','inject-php-sql',null)); F=F.concat(runPats(code,PHP_CMD,'INJECT','inject-php-cmd',null)); }
  if(lang==='java'||lang==='generic'){   F=F.concat(runPats(code,JAVA_SQL,'INJECT','inject-java-sql',null)); F=F.concat(runPats(code,JAVA_CMD,'INJECT','inject-java-cmd',null)); }
  if(lang==='go'||lang==='generic'){     F=F.concat(runPats(code,GO_SQL,'INJECT','inject-go-sql',null)); F=F.concat(runPats(code,GO_CMD,'INJECT','inject-go-cmd',null)); }
  if(lang==='ruby'||lang==='generic'){   F=F.concat(runPats(code,RUBY_SQL,'INJECT','inject-ruby-sql',null)); F=F.concat(runPats(code,RUBY_CMD,'INJECT','inject-ruby-cmd',null)); }
  if(lang==='csharp'||lang==='generic')  F=F.concat(runPats(code,CS_SQL,'INJECT','inject-cs-sql',null));
  return F;
}

=======
>>>>>>> 921b7bd (- IP and Domain/URL Scanner updated\n- Added New sources like wayback, BGP, crt.sh, etc to the scanners.\n- Added the restroing functionality to the history options.\n- Now the IP and URL/Domain Scanner can gather too much information about the Geo Location and other information.\n- The Code Auditor got improved.)
function detectInsecureStorage(code) {
  var F=[], lines=code.split('\n');
  [{re:/localStorage\.setItem\s*\(\s*['"][^'"]*['"]\s*,\s*(?:.*token|.*password|.*secret|.*jwt|.*auth)/gi,title:'Token/password stored in localStorage',sev:'high',desc:'Sensitive data in localStorage accessible to all JS on the page.'},{re:/sessionStorage\.setItem\s*\(\s*['"][^'"]*['"]\s*,\s*(?:.*token|.*password|.*jwt)/gi,title:'Token stored in sessionStorage',sev:'medium',desc:'sessionStorage exfiltrable via XSS.'},{re:/document\.cookie\s*=[^;](?!.*HttpOnly)(?!.*Secure)/gi,title:'Cookie set without Secure/HttpOnly flags',sev:'high',desc:'Cookies without Secure/HttpOnly stolen via sniffing or XSS.'}].forEach(function(p){
    var re=new RegExp(p.re.source,p.re.flags),m;
    while((m=re.exec(code))!==null){var ln=lineOf(code,m.index);F.push({id:'storage-'+ln,type:'STORAGE',title:p.title,sev:p.sev,loc:'line '+ln,line:ln,snippet:lines[ln-1]?lines[ln-1].trim():m[0],match:m[0].slice(0,80),desc:p.desc,remediation:{text:'Store tokens in memory or HttpOnly cookies set server-side.',fix:'// Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict'},confidence:85,taint:null});}
  });
  return F;
}

function detectDeserialization(code) {
  var F=[], lang=detectLanguage(code);
  if(lang==='python'||lang==='generic') F=F.concat(runPats(code,PY_DESERIAL,'DESERIAL','deserial-py',null));
  if(lang==='php'   ||lang==='generic') F=F.concat(runPats(code,PHP_DESERIAL,'DESERIAL','deserial-php',null));
  if(lang==='java'  ||lang==='generic') F=F.concat(runPats(code,JAVA_DESERIAL,'DESERIAL','deserial-java',null));
  if(lang==='ruby'  ||lang==='generic') F=F.concat(runPats(code,RUBY_DESERIAL,'DESERIAL','deserial-ruby',null));
  return F;
}

function detectPathTraversal(code) {
  var F=[], lang=detectLanguage(code), lines=code.split('\n');
  if(lang==='python'||lang==='generic'){
    runPats(code,PY_PATH,'PATH','path-py',null).forEach(function(f){
      // Suppress path traversal finding if secure_filename() is used within 5 lines above the match
      var lineIdx = f.line - 1;
      var windowStart = Math.max(0, lineIdx - 5);
      var nearbyLines = lines.slice(windowStart, lineIdx + 1).join('\n');
      if(/secure_filename\s*\(/.test(nearbyLines)) return; // already sanitized
      F.push(f);
    });
  }
  if(lang==='php'||lang==='generic') F=F.concat(runPats(code,PHP_FILE,'PATH','path-php',null));
  return F;
}

function detectSSRF(code) {
  var F=[], lang=detectLanguage(code), lines=code.split('\n');
  if(lang==='python'||lang==='generic'){
    runPats(code,PY_SSRF,'SSRF','ssrf-py',null).forEach(function(f){
      // Suppress "missing timeout" if the matched line itself contains timeout=
      var lineText = lines[f.line-1] || '';
      if(f.title.indexOf('timeout') !== -1 && /timeout\s*=/.test(lineText)) return;
      F.push(f);
    });
  }
  if(lang==='go'&&lang==='generic') F=F.concat(runPats(code,GO_SSRF,'SSRF','ssrf-go',null));
  return F;
}

function detectXXE(code) {
  var F=[], lang=detectLanguage(code);
  if(lang==='java'  ||lang==='generic') F=F.concat(runPats(code,JAVA_XXE,'XXE','xxe-java',null));
  if(lang==='csharp'||lang==='generic') F=F.concat(runPats(code,CS_XXE,'XXE','xxe-cs',null));
  return F;
}

function detectBufferOverflow(code) {
  var lang=detectLanguage(code);
  if(lang!=='cpp'&&lang!=='generic') return [];
  return runPats(code,CPP_VULNS,'BUFFER','buffer-c',null);
}

function detectShellIssues(code) {
  var lang=detectLanguage(code);
  if(lang!=='shell'&&lang!=='generic') return [];
  return runPats(code,SHELL_VULNS,'SHELL','shell',null);
}

function detectRustIssues(code) {
  var lang=detectLanguage(code);
  if(lang!=='rust'&&lang!=='generic') return [];
  return runPats(code,RUST_VULNS,'RUST','rust',null);
}

function detectDuplicates(code) {
  var lines=code.split('\n').map(function(l){return l.trim();}).filter(function(l){return l.length>40;});
  var count={};
  lines.forEach(function(l){count[l]=(count[l]||0)+1;});
  var dups=Object.keys(count).filter(function(k){return count[k]>4;});
  if(!dups.length) return [];
  return dups.slice(0,3).map(function(dup,i){
    return {id:'dup-'+i,type:'LOGIC',title:'Duplicate code block',sev:'medium',loc:'multiple lines',line:1,snippet:dup.slice(0,80),match:'duplicate',desc:'Snippet repeated '+count[dup]+' times.',remediation:{text:'Extract to a shared helper function.',fix:'function helper() { /* shared logic */ }'},confidence:70,taint:null};
  });
<<<<<<< HEAD
}
=======
}
/* ══════════════════════════════════════════
   KOTLIN / SWIFT / SQL INJECTION PATTERNS
══════════════════════════════════════════ */

var KOTLIN_SQL = [
  {re:/rawQuery\s*\(\s*[\"'].*[\"']\s*\+/gi, title:'SQL Injection — rawQuery() + concat (Kotlin/Android)', sev:'critical', desc:'String concatenation in rawQuery() → SQL injection.', fix:'db.rawQuery("SELECT * FROM t WHERE id = ?", arrayOf(userInput))'},
  {re:/execSQL\s*\(\s*[\"'].*[\"']\s*\+/gi, title:'SQL Injection — execSQL() + concat (Kotlin/Android)', sev:'critical', desc:'String concat in execSQL() is injectable.', fix:'Use parameterized queries with ? placeholders.'},
];

var SWIFT_SQL = [
  {re:/sqlite3_exec\s*\([^,]+,\s*(?:[^,]*\+|String\s*\(format:)/gi, title:'SQL Injection — sqlite3_exec() with concat (Swift)', sev:'critical', desc:'sqlite3_exec() with string interpolation/format → injectable.', fix:'Use prepared statements with sqlite3_prepare_v2.'},
  {re:/execute\s*\(\s*['\"]\s*\\\\?\(\w+\)/gi, title:'SQL Injection — execute() with Swift string interpolation', sev:'critical', desc:'String interpolation \\() in SQL → injectable.', fix:'Use ? placeholders and bind parameters.'},
];

var SQL_INJECT = [
  {re:/(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;]*\+\s*\w+/gi, title:'SQL Injection — dynamic SQL concatenation', sev:'critical', desc:'Direct string concatenation in SQL statement — user input can break query structure.', fix:'Use parameterized queries with ? or $N placeholders.'},
  {re:/EXEC(?:UTE)?\s+\(\s*@\w+\s*\)/gi, title:'SQL Injection — dynamic EXEC() in stored procedure', sev:'critical', desc:'EXEC() with variable argument in SQL → dynamic SQL injection.', fix:'Use sp_executesql with @params parameter.'},
];

function detectInjection(code) {
  var F = [], lang = detectLanguage(code), lines = code.split('\n');

  function jsPat(re, id, title, sev, desc, fix) {
    var r = new RegExp(re.source, re.flags), m;
    while ((m = r.exec(code)) !== null) {
      var ln = lineOf(code, m.index);
      F.push({ id: id+'-'+ln, type:'INJECT', title:title, sev:sev,
        loc:'line '+ln, line:ln,
        snippet: lines[ln-1] ? lines[ln-1].trim() : m[0],
        match: m[0].slice(0,80),
        desc: desc,
        remediation: { text:'Use parameterized queries or safe APIs.', fix:fix },
        confidence: 88, taint:{ source:'user-controlled input', flow:['unsanitized'], sink:title }
      });
    }
  }

  if (lang==='js'||lang==='typescript'||lang==='generic') {
    jsPat(/["'`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\s[^"'`]*["'`]\s*\+/gi,
      'inject-js-sql','SQL injection — string concat (JS)','critical',
      'SQL query built with string concatenation.', "db.query('SELECT * FROM t WHERE id=?',[id])");
    jsPat(/exec\s*\(\s*["'`].*\+|execSync\s*\([^)]*\+/g,
      'inject-js-cmd','Command injection — dynamic exec (JS)','critical',
      'User input may reach shell exec.', "spawn('cmd',[arg],{shell:false})");
  }
  if (lang==='python'||lang==='generic') {
    F = F.concat(runPats(code, PY_SQL,  'INJECT','inject-py-sql', null));
    F = F.concat(runPats(code, PY_CMD,  'INJECT','inject-py-cmd', null));
  }
  if (lang==='php'||lang==='generic') {
    F = F.concat(runPats(code, PHP_SQL, 'INJECT','inject-php-sql',null));
    F = F.concat(runPats(code, PHP_CMD, 'INJECT','inject-php-cmd',null));
  }
  if (lang==='java'||lang==='generic') {
    F = F.concat(runPats(code, JAVA_SQL,'INJECT','inject-java-sql',null));
    F = F.concat(runPats(code, JAVA_CMD,'INJECT','inject-java-cmd',null));
  }
  if (lang==='go'||lang==='generic') {
    F = F.concat(runPats(code, GO_SQL,  'INJECT','inject-go-sql', null));
    F = F.concat(runPats(code, GO_CMD,  'INJECT','inject-go-cmd', null));
  }
  if (lang==='ruby'||lang==='generic') {
    F = F.concat(runPats(code, RUBY_SQL,'INJECT','inject-ruby-sql',null));
    F = F.concat(runPats(code, RUBY_CMD,'INJECT','inject-ruby-cmd',null));
  }
  if (lang==='csharp'||lang==='generic')
    F = F.concat(runPats(code, CS_SQL,  'INJECT','inject-cs-sql', null));
  if (lang==='kotlin'||lang==='generic')
    F = F.concat(runPats(code, KOTLIN_SQL,'INJECT','inject-kotlin-sql',null));
  if (lang==='swift'||lang==='generic')
    F = F.concat(runPats(code, SWIFT_SQL, 'INJECT','inject-swift-sql',null));
  if (lang==='sql')
    F = F.concat(runPats(code, SQL_INJECT,'INJECT','inject-sql',null));
  return F;
}

>>>>>>> 921b7bd (- IP and Domain/URL Scanner updated\n- Added New sources like wayback, BGP, crt.sh, etc to the scanners.\n- Added the restroing functionality to the history options.\n- Now the IP and URL/Domain Scanner can gather too much information about the Geo Location and other information.\n- The Code Auditor got improved.)
