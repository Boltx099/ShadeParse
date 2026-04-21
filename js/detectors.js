// ShadeParse — detectors.js
// FIXED: Expanded rules, credential extraction, broader vulnerability coverage.

const RULES = [
  // API KEYS / TOKENS
  {id:'hardcoded-api-key',    name:'Hardcoded API key',          pat:/["']?(?:api[_-]?key|apiKey|API_KEY|x-api-key)["']?\s*[=:]\s*["']([A-Za-z0-9\-_]{20,})["']/gi, sev:'critical', type:'SECRET', enabled:true},
  {id:'stripe-live-key',      name:'Stripe live secret key',     pat:/sk_live_[A-Za-z0-9]{16,}/g,                                                                    sev:'critical', type:'SECRET', enabled:true},
  {id:'stripe-pub-key',       name:'Stripe publishable key',     pat:/pk_live_[A-Za-z0-9]{16,}/g,                                                                    sev:'high',     type:'SECRET', enabled:true},
  {id:'aws-access-key',       name:'AWS access key ID',          pat:/AKIA[0-9A-Z]{16}/g,                                                                             sev:'critical', type:'SECRET', enabled:true},
  {id:'aws-secret-key',       name:'AWS secret access key',      pat:/(?:aws[_-]?secret[_-]?(?:access[_-]?)?key)["'\s]*[=:][\s]*["']([A-Za-z0-9+\/]{40})["']/gi,   sev:'critical', type:'SECRET', enabled:true},
  {id:'slack-token',          name:'Slack bot token',            pat:/xoxb-[0-9A-Za-z\-]{30,}/g,                                                                     sev:'critical', type:'SECRET', enabled:true},
  {id:'slack-user-token',     name:'Slack user token',           pat:/xoxp-[0-9A-Za-z\-]{30,}/g,                                                                     sev:'critical', type:'SECRET', enabled:true},
  {id:'github-pat',           name:'GitHub personal access token',pat:/ghp_[A-Za-z0-9]{36}/g,                                                                        sev:'critical', type:'SECRET', enabled:true},
  {id:'github-oauth',         name:'GitHub OAuth token',         pat:/gho_[A-Za-z0-9]{36}/g,                                                                         sev:'critical', type:'SECRET', enabled:true},
  {id:'jwt-secret',           name:'JWT secret hardcoded',       pat:/["']?jwt[_-]?secret["']?\s*[=:]\s*["']([^"']{8,})["']/gi,                                     sev:'critical', type:'SECRET', enabled:true},
  {id:'jwt-token',            name:'JWT token in source',        pat:/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,                             sev:'high',     type:'SECRET', enabled:true},
  {id:'google-api',           name:'Google API key',             pat:/AIza[0-9A-Za-z\-_]{35}/g,                                                                      sev:'critical', type:'SECRET', enabled:true},
  {id:'google-oauth',         name:'Google OAuth client secret', pat:/["']?client_secret["']?\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,                            sev:'critical', type:'SECRET', enabled:true},
  {id:'twilio-sid',           name:'Twilio account SID',         pat:/AC[a-z0-9]{32}/g,                                                                               sev:'high',     type:'SECRET', enabled:true},
  {id:'sendgrid-key',         name:'SendGrid API key',           pat:/SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43}/g,                                                sev:'critical', type:'SECRET', enabled:true},
  {id:'firebase-config',      name:'Firebase config exposed',    pat:/firebaseConfig|initializeApp\s*\(.*authDomain\s*:/gs,                                           sev:'high',     type:'SECRET', enabled:true},
  {id:'private-key-block',    name:'Private key in source',      pat:/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,                                            sev:'critical', type:'SECRET', enabled:true},
  {id:'db-conn-string',       name:'DB connection string',       pat:/mongodb(\+srv)?:\/\/[^"'\s]{10,}/g,                                                             sev:'critical', type:'SECRET', enabled:true},
  {id:'postgres-conn',        name:'PostgreSQL connection string',pat:/postgres(?:ql)?:\/\/[^"'\s]{10,}/g,                                                            sev:'critical', type:'SECRET', enabled:true},
  {id:'mysql-conn',           name:'MySQL connection string',    pat:/mysql:\/\/[^"'\s]{10,}/g,                                                                       sev:'critical', type:'SECRET', enabled:true},
  {id:'redis-conn',           name:'Redis connection string',    pat:/redis(?:s)?:\/\/[^"'\s]{10,}/g,                                                                 sev:'high',     type:'SECRET', enabled:true},
];

const CRED_PATTERNS = [
  {id:'hardcoded-password',   pat:/["']?(?:password|passwd|pwd|pass|secret)["']?\s*[=:]\s*["']([^"'${}()\s]{6,})["']/gi,   name:'Hardcoded password',        sev:'critical'},
  {id:'hardcoded-username',   pat:/["']?(?:username|user|login|email|USER)["']?\s*[=:]\s*["']([a-zA-Z0-9._@+\-]{4,})["']/gi,name:'Hardcoded username/email', sev:'high'},
  {id:'basic-auth-header',    pat:/Authorization\s*:\s*["']?Basic\s+([A-Za-z0-9+\/=]{8,})["']?/gi,                          name:'Basic auth credentials',    sev:'critical'},
  {id:'bearer-token',         pat:/Authorization\s*:\s*["']?Bearer\s+([A-Za-z0-9\-._~+\/=]{20,})["']?/gi,                   name:'Bearer token hardcoded',    sev:'critical'},
  {id:'admin-creds',          pat:/["']?(?:admin_pass|ADMIN_PASSWORD|root_pass|ROOT_PASS)["']?\s*[=:]\s*["']([^"']{4,})["']/gi, name:'Admin credentials',     sev:'critical'},
];

const MALICIOUS_PKGS = [
  'flatmap-stream','event-stream','ua-parser-js','colors','coa','rc','node-ipc',
  'peacenotwar','lodash.template','klow','klown',
];

const MOD_INFO = [
  {name:'Secret Detection',      type:'SECRET',  det:'20+ patterns',                              desc:'Scans for hardcoded API keys, tokens, and connection strings.',isNew:false},
  {name:'Credential Extraction', type:'CRED',    det:'Username, password, Basic/Bearer headers',  desc:'Detects hardcoded usernames, passwords, and auth headers.',isNew:false},
  {name:'Endpoint Discovery',    type:'ENDPOINT',det:'Route graph + internal paths',              desc:'Extracts undocumented API routes and admin panels.',isNew:false},
  {name:'DOM XSS / Taint',       type:'XSS',     det:'Source to sink, postMessage, eval',         desc:'Traces user-controlled data to dangerous sinks.',isNew:true},
  {name:'Prototype Pollution',   type:'PROTO',   det:'Recursive merge, jQuery extend',            desc:'Detects unsafe object merge patterns.',isNew:true},
  {name:'Weak Cryptography',     type:'CRYPTO',  det:'MD5, SHA1, DES, Math.random, bad IVs',     desc:'Flags broken hash and cipher algorithms.',isNew:true},
  {name:'Supply Chain Scanner',  type:'SUPPLY',  det:'Malicious packages + suspicious CDNs',     desc:'Cross-references imports against known compromised packages.',isNew:true},
  {name:'Logic Flaw Analysis',   type:'LOGIC',   det:'localStorage authz, bypass patterns',      desc:'Detects client-side authorization bypasses.',isNew:false},
  {name:'Config Analysis',       type:'CONFIG',  det:'Debug flags, dev mode, CORS, cookies',     desc:'Identifies insecure configuration in production bundles.',isNew:false},
  {name:'Injection Detection',   type:'INJECT',  det:'SQL, command, template injection',         desc:'Detects unsanitized input in dangerous sinks.',isNew:true},
  {name:'Insecure Storage',      type:'STORAGE', det:'localStorage/sessionStorage/cookies',      desc:'Flags sensitive data stored insecurely client-side.',isNew:true},
];

function lineOf(code, idx) {
  return code.slice(0, idx).split('\n').length;
}

function snip(code, ln) {
  return (code.split('\n')[ln - 1] || '').trim().slice(0, 160);
}

/* SECRET SCANNER */
function detectSecrets(code) {
  const F = [];
  RULES.filter(r => r.enabled && r.type === 'SECRET').forEach(rule => {
    const re = new RegExp(rule.pat.source, rule.pat.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const ln = lineOf(code, m.index);
      F.push({
        id: rule.id,
        type: 'SECRET',
        title: rule.name,
        sev: rule.sev,
        loc: 'line ' + ln,
        line: ln,
        snippet: snip(code, ln),
        match: m[0].slice(0, 80),
        desc: 'A ' + rule.name.toLowerCase() + ' was found hardcoded. This credential may allow unauthorized access.',
        remediation: {
          text: 'Remove from client-side code. Store server-side via environment variables or a secrets manager.',
          fix: '// Before\nconst KEY = "' + m[0].slice(0, 20) + '...";\n\n// After\nconst KEY = process.env.SECRET_KEY;'
        },
        confidence: 92,
        taint: null
      });
    }
  });
  return F;
}

/* CREDENTIAL EXTRACTOR */
function detectCredentials(code) {
  const F = [];
  CRED_PATTERNS.forEach(rule => {
    const re = new RegExp(rule.pat.source, rule.pat.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const captured = m[1] || m[0];
      if (/process\.env|getenv|\$\{|ENV\[/.test(captured)) continue;
      if (captured.length < 4 || /^(your|xxx|test|demo|example|placeholder|changeme|replace|password|secret)$/i.test(captured)) continue;
      const ln = lineOf(code, m.index);
      F.push({
        id: rule.id + '-' + ln,
        type: 'CRED',
        title: rule.name,
        sev: rule.sev,
        loc: 'line ' + ln,
        line: ln,
        snippet: snip(code, ln),
        match: m[0].slice(0, 80),
        desc: 'Hardcoded credential "' + captured.slice(0, 40) + '" found. Exposing credentials allows unauthorized access.',
        remediation: {
          text: 'Never hardcode credentials. Use environment variables or a vault service.',
          fix: '// Before\nconst password = "' + captured.slice(0, 12) + '...";\n\n// After\nconst password = process.env.DB_PASSWORD;'
        },
        confidence: 88,
        taint: null
      });
    }
  });
  return F;
}

/* ENDPOINT SCANNER */
function detectEndpoints(code) {
  const F = [];
  const pats = [
    {re: /["'`](\/(admin|administrator|wp-admin|panel|manage)[\w\-\/?=&]*)/gi,  label: 'Admin endpoint',           sev: 'high'},
    {re: /["'`](\/(debug|test|staging|dev|sandbox)[\w\-\/?=&]*)/gi,             label: 'Debug/dev route',          sev: 'high'},
    {re: /["'`](\/api\/(?:v\d\/)?(?:private|internal|export|admin|superadmin)[\w\-\/?=&]*)/gi, label: 'Internal API route', sev: 'medium'},
    {re: /["'`](\/(internal|private)\/[\w\-\/?=&]*)/gi,                          label: 'Private service path',     sev: 'medium'},
    {re: /["'`](\/graphql(?:\/[\w\-\/?=&]*)?)/gi,                                label: 'GraphQL endpoint',         sev: 'medium'},
    {re: /["'`](\/\.env|\/\.git\/config|\/config\.json|\/secrets\.json)/gi,      label: 'Sensitive file path',      sev: 'critical'},
    {re: /["'`](\/actuator(?:\/[\w\-\/?=&]*)?)/gi,                               label: 'Spring actuator endpoint', sev: 'high'},
    {re: /["'`](\/swagger(?:-ui)?(?:\/[\w\-\/?=&]*)?)/gi,                        label: 'Swagger docs exposed',     sev: 'low'},
  ];
  pats.forEach(p => {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const ln = lineOf(code, m.index);
      F.push({
        id: 'endpoint-' + p.label.replace(/\s/g,'-').toLowerCase() + '-' + ln,
        type: 'ENDPOINT',
        title: p.label + ' exposed',
        sev: p.sev,
        loc: 'line ' + ln,
        line: ln,
        snippet: snip(code, ln),
        match: m[1] || m[0],
        desc: 'Endpoint "' + (m[1] || m[0]) + '" found in client bundle. May expose sensitive functionality to attackers.',
        remediation: {text: 'Verify server-side auth. Remove internal paths from client route maps.', fix: '// Keep internal routes server-side only'},
        confidence: 80,
        taint: null
      });
    }
  });
  return F;
}

/* DOM XSS */
function detectXSS(code) {
  const F = [];
  const lines = code.split('\n');
  const sources = /location\.(hash|search|href|pathname)|URLSearchParams|document\.referrer|window\.name|params\.get\(/;

  if (sources.test(code)) {
    [
      {re: /innerHTML\s*=/g,            sink: 'innerHTML',            title: 'DOM XSS — innerHTML sink'},
      {re: /outerHTML\s*=/g,            sink: 'outerHTML',            title: 'DOM XSS — outerHTML sink'},
      {re: /document\.write\s*\(/g,     sink: 'document.write()',     title: 'DOM XSS — document.write sink'},
      {re: /\.insertAdjacentHTML\s*\(/g,sink: 'insertAdjacentHTML()', title: 'DOM XSS — insertAdjacentHTML sink'},
      {re: /eval\s*\(/g,                sink: 'eval()',               title: 'DOM XSS — eval() sink'},
      {re: /new\s+Function\s*\(/g,      sink: 'new Function()',       title: 'DOM XSS — new Function() sink'},
    ].forEach(p => {
      const re = new RegExp(p.re.source, p.re.flags);
      let m;
      while ((m = re.exec(code)) !== null) {
        const ln = lineOf(code, m.index);
        F.push({
          id: 'xss-' + p.sink.replace(/[^a-z]/gi,'-') + '-' + ln,
          type: 'XSS', title: p.title, sev: 'critical',
          loc: 'line ' + ln, line: ln,
          snippet: lines[ln-1] ? lines[ln-1].trim() : '',
          match: m[0],
          desc: 'User-controlled data may reach ' + p.sink + ' without sanitization. Allows script injection.',
          remediation: {text: 'Sanitize all user input. Use DOMPurify or textContent instead.', fix: "import DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize(untrustedInput);"},
          confidence: 90,
          taint: {source: 'location.hash / URLSearchParams', flow: ['unsanitized'], sink: p.sink}
        });
      }
    });
  }

  if (/addEventListener\s*\(\s*['"]message['"]/.test(code) && !/event\.origin|e\.origin/.test(code)) {
    const ln = lines.findIndex(l => /addEventListener\s*\(\s*['"]message['"]/.test(l)) + 1;
    if (ln > 0) F.push({
      id: 'xss-postmessage-no-origin-' + ln,
      type: 'XSS', title: 'postMessage without origin check', sev: 'high',
      loc: 'line ' + ln, line: ln, snippet: lines[ln-1].trim(), match: 'addEventListener("message")',
      desc: 'postMessage listener does not validate event.origin, allowing cross-origin message injection.',
      remediation: {text: 'Always validate event.origin before processing.', fix: "window.addEventListener('message', (e) => {\n  if (e.origin !== 'https://trusted.com') return;\n});"},
      confidence: 85,
      taint: {source: 'window.postMessage', flow: ['event.data'], sink: 'unvalidated handler'}
    });
  }
  return F;
}

/* PROTOTYPE POLLUTION */
function detectProto(code) {
  const F = [];
  const lines = code.split('\n');
  [
    {re: /for\s*\(\s*(const|let|var)?\s*key\s+in\s+\w+\s*\)(?![^{]*hasOwnProperty)/g, title: 'Prototype pollution — unsafe for..in merge',          confidence: 85},
    {re: /Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|request\.|user\.)/g,               title: 'Prototype pollution — Object.assign with user input', confidence: 80},
    {re: /\$\.extend\s*\(\s*true/g,                                                     title: 'Prototype pollution — jQuery deep extend',           confidence: 90},
  ].forEach(p => {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const ln = lineOf(code, m.index);
      F.push({
        id: 'proto-' + ln,
        type: 'PROTO', title: p.title, sev: 'critical',
        loc: 'line ' + ln, line: ln,
        snippet: lines[ln-1] ? lines[ln-1].trim() : m[0],
        match: m[0].slice(0, 60),
        desc: 'Unsafe object merge without __proto__ guards. Attackers can pollute Object.prototype.',
        remediation: {text: 'Guard dangerous keys or use Object.create(null).', fix: 'const UNSAFE = ["__proto__","constructor","prototype"];\nfor (const key of Object.keys(src)) {\n  if (UNSAFE.includes(key)) continue;\n  target[key] = src[key];\n}'},
        confidence: p.confidence, taint: null
      });
    }
  });
  return F;
}

/* SUPPLY CHAIN */
function detectSupply(code) {
  const F = [];
  const importRe  = /import\s+(?:\w+\s+from\s+)?['"]([^'"]+)['"]/g;
  const requireRe = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  const cdnRe     = /src\s*=\s*["'](https?:\/\/(?!cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|fonts\.googleapis\.com)[^"']+\.js)["']/gi;
  const pkgs = [];
  let m;
  while ((m = importRe.exec(code))  !== null) pkgs.push({name: m[1], idx: m.index});
  while ((m = requireRe.exec(code)) !== null) pkgs.push({name: m[1], idx: m.index});
  MALICIOUS_PKGS.forEach(pkg => {
    const hit = pkgs.find(p => p.name === pkg || p.name.startsWith(pkg + '/'));
    if (hit) {
      const ln = lineOf(code, hit.idx);
      F.push({
        id: 'supply-' + pkg, type: 'SUPPLY', title: 'Supply chain risk — ' + pkg, sev: 'critical',
        loc: 'line ' + ln, line: ln, snippet: snip(code, ln), match: pkg,
        desc: '"' + pkg + '" has a known supply chain compromise. Malicious code injected into the package.',
        remediation: {text: 'Remove immediately. Run: npm audit --fix', fix: '// Remove from package.json\n// Run: npm audit fix && npm ci'},
        confidence: 99, taint: null
      });
    }
  });
  const re2 = new RegExp(cdnRe.source, cdnRe.flags);
  while ((m = re2.exec(code)) !== null) {
    const ln = lineOf(code, m.index);
    F.push({
      id: 'supply-cdn-' + ln, type: 'SUPPLY', title: 'Unrecognized external CDN script', sev: 'medium',
      loc: 'line ' + ln, line: ln, snippet: snip(code, ln), match: m[1].slice(0,80),
      desc: 'Script loaded from unrecognized CDN "' + m[1].slice(0,60) + '". If compromised, delivers code to all users.',
      remediation: {text: 'Self-host scripts or use a trusted, SRI-protected CDN.', fix: '<script src="..." integrity="sha384-..." crossorigin="anonymous">'},
      confidence: 70, taint: null
    });
  }
  return F;
}

/* WEAK CRYPTO */
function detectCrypto(code) {
  const F = [];
  [
    {re: /require\s*\(\s*['"]md5['"]\s*\)|createHash\s*\(\s*['"]md5['"]\s*\)/g,               title: 'MD5 used for hashing',             sev: 'high',     fix: "crypto.createHash('sha256').update(data).digest('hex')"},
    {re: /createHash\s*\(\s*['"]sha1['"]\s*\)/g,                                               title: 'SHA-1 used for hashing',           sev: 'high',     fix: "crypto.createHash('sha256').update(data).digest('hex')"},
    {re: /Math\.random\s*\(\s*\)\s*\*\s*[0-9]+|Math\.random\s*\(\s*\)\.toString/g,            title: 'Math.random() for security tokens', sev: 'high',     fix: 'crypto.getRandomValues(new Uint8Array(32))'},
    {re: /createCipheriv\s*\(\s*['"](?:des|des-ecb|des-cbc|rc4)['"]/gi,                       title: 'Broken cipher (DES/RC4)',           sev: 'critical', fix: "crypto.createCipheriv('aes-256-gcm', key, iv)"},
    {re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]/gi,     title: 'TLS certificate verification disabled', sev:'critical', fix:"// Remove rejectUnauthorized: false"},
    {re: /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\s*\)[^]*?password|password[^]*?Buffer\.from/gi, title:'Base64-encoded password (not encrypted)', sev:'high', fix:'Use bcrypt or Argon2 for password storage'},
  ].forEach(p => {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const ln = lineOf(code, m.index);
      F.push({
        id: 'crypto-' + p.title.replace(/\s+/g,'-').toLowerCase() + '-' + ln,
        type: 'CRYPTO', title: p.title, sev: p.sev,
        loc: 'line ' + ln, line: ln, snippet: snip(code, ln), match: m[0].slice(0,60),
        desc: p.title + ' detected. Weak/broken cryptography can be defeated by attackers.',
        remediation: {text: 'Replace with a modern, secure algorithm.', fix: p.fix},
        confidence: 92, taint: null
      });
    }
  });
  return F;
}

/* LOGIC FLAWS */
function detectLogic(code) {
  const F = [];
  const lines = code.split('\n');
  [
    {re: /localStorage\.getItem\s*\(.*\)\s*===\s*['"](?:true|1|admin)['"]/g, title: 'Authorization via localStorage (bypassable)', sev:'critical', desc:'Auth decisions based on localStorage are trivially bypassable via DevTools.', fix:'const res = await fetch("/api/auth/check");\nif (!res.ok) redirect("/login");'},
    {re: /if\s*\(\s*(?:is_?admin|isAdmin|role\s*===\s*['"]admin)\s*\)/g,     title: 'Client-side admin role check',               sev:'high',     desc:'Role checks in client-side code can be bypassed by modifying the variable in DevTools.', fix:'// Validate roles on the server, not the client'},
    {re: /window\.location\.(href|replace)\s*=.*(?:req\.|params\.|query\.)/gi,title:'Open redirect via location manipulation',    sev:'high',     desc:'Unvalidated redirect target can send users to attacker-controlled sites.', fix:'const ALLOWED = ["/home","/dashboard"];\nif (ALLOWED.includes(target)) location.href = target;'},
  ].forEach(p => {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const ln = lineOf(code, m.index);
      F.push({
        id: 'logic-' + p.title.replace(/\s/g,'-').toLowerCase() + '-' + ln,
        type: 'LOGIC', title: p.title, sev: p.sev,
        loc: 'line ' + ln, line: ln,
        snippet: lines[ln-1] ? lines[ln-1].trim() : m[0],
        match: m[0].slice(0,60), desc: p.desc,
        remediation: {text: 'Move all authorization logic server-side.', fix: p.fix},
        confidence: 85, taint: null
      });
    }
  });
  return F;
}

/* CONFIG ANALYSIS */
function detectConfig(code) {
  const F = [];
  [
    {re: /\bDEBUG\s*=\s*true\b|\bdebug\s*:\s*true\b/gi,                                                   title:'Debug mode enabled in bundle',       sev:'medium'},
    {re: /console\.(log|debug|info)\s*\(.*(?:password|token|secret|key|auth)/gi,                           title:'Sensitive data logged to console',    sev:'high'},
    {re: /Access-Control-Allow-Origin['":\s]*\*/gi,                                                        title:'CORS wildcard origin (*) allowed',    sev:'high'},
    {re: /secure\s*:\s*false|httpOnly\s*:\s*false/gi,                                                      title:'Insecure cookie configuration',       sev:'high'},
    {re: /rejectUnauthorized\s*:\s*false/gi,                                                               title:'TLS cert verification disabled',      sev:'critical'},
    {re: /sourceMappingURL=.*\.map/g,                                                                      title:'Source map URL in production bundle', sev:'low'},
  ].forEach(p => {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const ln = lineOf(code, m.index);
      F.push({
        id: 'config-' + p.title.replace(/\s/g,'-').toLowerCase() + '-' + ln,
        type: 'CONFIG', title: p.title, sev: p.sev,
        loc: 'line ' + ln, line: ln, snippet: snip(code, ln), match: m[0].slice(0,60),
        desc: '"' + m[0].slice(0,50) + '" found in bundle. This may expose internals or weaken security.',
        remediation: {text: 'Use build-time env vars to strip debug/insecure flags in production.', fix: "new webpack.DefinePlugin({'__DEV__': JSON.stringify(false)})"},
        confidence: 80, taint: null
      });
    }
  });
  return F;
}

/* INJECTION DETECTION */
function detectInjection(code) {
  const F = [];
  const lines = code.split('\n');
  [
    {re: /["'`]SELECT\s.+FROM\s.+["'`]\s*\+|query\s*\(\s*["'`].*\+\s*(?:req\.|params\.|user\.)/gi, title:'SQL injection — string concatenation',   sev:'critical', desc:'Unsanitized user input in SQL query. Allows attackers to read/modify the database.', fix:"// Use parameterized queries:\ndb.query('SELECT * FROM users WHERE id = ?', [userId])"},
    {re: /exec\s*\(\s*["'`].*\+|execSync\s*\([^)]*\+|child_process.*\+/g,                          title:'Command injection — dynamic exec',        sev:'critical', desc:'User input may reach shell exec/spawn, allowing arbitrary OS command execution.', fix:"spawn('cmd', [arg1, arg2], { shell: false })"},
    {re: /new\s+RegExp\s*\(\s*(?:req\.|params\.|user\.|input)/gi,                                    title:'ReDoS — user-controlled RegExp',          sev:'high',     desc:'User input as a RegExp pattern can trigger catastrophic backtracking.', fix:"const safe = input.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');"},
  ].forEach(p => {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const ln = lineOf(code, m.index);
      F.push({
        id: 'inject-' + p.title.replace(/\s/g,'-').toLowerCase() + '-' + ln,
        type: 'INJECT', title: p.title, sev: p.sev,
        loc: 'line ' + ln, line: ln,
        snippet: lines[ln-1] ? lines[ln-1].trim() : m[0],
        match: m[0].slice(0,80), desc: p.desc,
        remediation: {text: 'Use parameterized queries or safe APIs that separate code from data.', fix: p.fix},
        confidence: 88,
        taint: {source: 'user-controlled input', flow: ['unsanitized'], sink: p.title}
      });
    }
  });
  return F;
}

/* INSECURE STORAGE */
function detectInsecureStorage(code) {
  const F = [];
  const lines = code.split('\n');
  [
    {re: /localStorage\.setItem\s*\(\s*['"][^'"]*['"],\s*(?:.*token|.*password|.*secret|.*jwt|.*auth)/gi, title:'Token/password stored in localStorage', sev:'high', desc:'Sensitive data in localStorage is accessible to any JS on the page (XSS risk).'},
    {re: /sessionStorage\.setItem\s*\(\s*['"][^'"]*['"],\s*(?:.*token|.*password|.*jwt)/gi,               title:'Token stored in sessionStorage',         sev:'medium', desc:'sessionStorage is accessible to scripts and can be exfiltrated via XSS.'},
    {re: /document\.cookie\s*=[^;](?!.*HttpOnly)(?!.*Secure)/gi,                                          title:'Cookie set without Secure/HttpOnly flags',sev:'high', desc:'Cookies without Secure and HttpOnly can be stolen via sniffing or XSS.'},
  ].forEach(p => {
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      const ln = lineOf(code, m.index);
      F.push({
        id: 'storage-' + p.title.replace(/\s/g,'-').toLowerCase() + '-' + ln,
        type: 'STORAGE', title: p.title, sev: p.sev,
        loc: 'line ' + ln, line: ln,
        snippet: lines[ln-1] ? lines[ln-1].trim() : m[0],
        match: m[0].slice(0,80), desc: p.desc,
        remediation: {text: 'Store tokens in memory or HttpOnly cookies set server-side.', fix: '// Use HttpOnly cookie from server:\n// Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict'},
        confidence: 85, taint: null
      });
    }
  });
  return F;
}

/* DUPLICATES */
function detectDuplicates(code) {
  const lines = code.split('\n').map(l => l.trim()).filter(l => l.length > 40);
  const count = {};
  lines.forEach(l => { count[l] = (count[l] || 0) + 1; });
  const dups = Object.keys(count).filter(k => count[k] > 4);
  if (dups.length === 0) return [];
  return dups.slice(0, 3).map((dup, i) => ({
    id: 'dup-' + i, type: 'LOGIC', title: 'Duplicate code block detected', sev: 'medium',
    loc: 'multiple lines', line: 1, snippet: dup.slice(0, 80), match: 'duplicate',
    desc: 'Snippet repeated ' + count[dup] + ' times. Increases maintenance burden and risk surface.',
    remediation: {text: 'Extract to a shared helper function.', fix: 'function helper() { /* shared logic */ }'},
    confidence: 70, taint: null
  }));
}
