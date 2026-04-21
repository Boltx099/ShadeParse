/**
 * ShadeParse — network.js
 * Domain, URL, and IP scan simulation.
 * Generates realistic recon output using client-side analysis.
 */

'use strict';

/* ─────────────────────────────────────────
   COMMON PORT DEFINITIONS
───────────────────────────────────────── */

var COMMON_PORTS = [
  { port: 21,   svc: 'FTP',      risk: 'high'    },
  { port: 22,   svc: 'SSH',      risk: 'medium'  },
  { port: 23,   svc: 'Telnet',   risk: 'critical'},
  { port: 25,   svc: 'SMTP',     risk: 'medium'  },
  { port: 53,   svc: 'DNS',      risk: 'info'    },
  { port: 80,   svc: 'HTTP',     risk: 'medium'  },
  { port: 110,  svc: 'POP3',     risk: 'medium'  },
  { port: 143,  svc: 'IMAP',     risk: 'medium'  },
  { port: 443,  svc: 'HTTPS',    risk: 'info'    },
  { port: 445,  svc: 'SMB',      risk: 'critical'},
  { port: 1433, svc: 'MSSQL',    risk: 'critical'},
  { port: 3306, svc: 'MySQL',    risk: 'critical'},
  { port: 3389, svc: 'RDP',      risk: 'critical'},
  { port: 5432, svc: 'Postgres', risk: 'critical'},
  { port: 6379, svc: 'Redis',    risk: 'critical'},
  { port: 8080, svc: 'HTTP-Alt', risk: 'medium'  },
  { port: 8443, svc: 'HTTPS-Alt',risk: 'medium'  },
  { port: 9200, svc: 'Elastic',  risk: 'critical'},
  { port: 27017,svc: 'MongoDB',  risk: 'critical'},
];

var SEC_HEADERS = [
  { name: 'Strict-Transport-Security', short: 'HSTS',            required: true  },
  { name: 'Content-Security-Policy',   short: 'CSP',             required: true  },
  { name: 'X-Frame-Options',           short: 'X-Frame-Options', required: true  },
  { name: 'X-Content-Type-Options',    short: 'X-Content-Type',  required: true  },
  { name: 'Referrer-Policy',           short: 'Referrer-Policy', required: false },
  { name: 'Permissions-Policy',        short: 'Permissions-Policy', required: false},
];

var SUBDOMAIN_PREFIXES = [
  'www','mail','ftp','smtp','pop','imap','vpn','remote','dev','staging',
  'api','app','blog','shop','admin','portal','cdn','static','media','files',
  'git','jenkins','jira','confluence','kibana','grafana','prometheus',
];

var TECH_STACKS = [
  { name: 'nginx',          cat: 'Web Server',   risk: 'info' },
  { name: 'Apache',         cat: 'Web Server',   risk: 'info' },
  { name: 'WordPress',      cat: 'CMS',          risk: 'warn' },
  { name: 'Drupal',         cat: 'CMS',          risk: 'warn' },
  { name: 'Joomla',         cat: 'CMS',          risk: 'warn' },
  { name: 'React',          cat: 'Frontend',     risk: 'info' },
  { name: 'Angular',        cat: 'Frontend',     risk: 'info' },
  { name: 'Vue.js',         cat: 'Frontend',     risk: 'info' },
  { name: 'jQuery',         cat: 'Library',      risk: 'info' },
  { name: 'PHP',            cat: 'Language',     risk: 'info' },
  { name: 'Laravel',        cat: 'Framework',    risk: 'info' },
  { name: 'Express.js',     cat: 'Framework',    risk: 'info' },
  { name: 'Cloudflare',     cat: 'WAF/CDN',      risk: 'info' },
  { name: 'AWS CloudFront', cat: 'CDN',          risk: 'info' },
  { name: 'Shopify',        cat: 'E-commerce',   risk: 'info' },
];

/* ─────────────────────────────────────────
   DETERMINISTIC PSEUDO-RANDOM
───────────────────────────────────────── */

function hashStr(s) {
  var h = 0;
  for (var i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

function seededRand(seed, n) {
  return ((seed * 1103515245 + 12345) & 0x7fffffff) % n;
}

/* ─────────────────────────────────────────
   RUN DOMAIN SCAN
───────────────────────────────────────── */

async function runNetworkScan() {
  var raw = (document.getElementById('targetInput').value || '').trim();
  if (!raw) { showToast('Enter a domain or URL first.', 'warn'); return; }

  // Parse target
  var target = raw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
  if (!target) { showToast('Invalid target.', 'error'); return; }

  // Block private / loopback / link-local addresses
  var _blocked = [
    /^localhost$/i,
    /^127\./,
    /^0\.0\.0\.0/,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^::1$/,
    /^fc[0-9a-f]{2}:/i,
    /^fe80:/i,
  ];
  if (_blocked.some(function(re) { return re.test(target); })) {
    showToast('Private or loopback addresses are not allowed.', 'error');
    if (btn) btn.disabled = false;
    return;
  }

  // Require at least one dot (hostname or IPv4) or a bracketed IPv6
  var _validHost = /^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$|^(\d{1,3}\.){3}\d{1,3}$|^\[.+\]$/i;
  if (!_validHost.test(target)) {
    showToast('Enter a valid domain, hostname, or IP address.', 'error');
    if (btn) btn.disabled = false;
    return;
  }

  // Disable button
  var btn = document.getElementById('targetScanBtn');
  if (btn) btn.disabled = true;

  setStatus('scanning');
  clearLog(APP.state);
  setProgress(0, 'Initializing...');
  renderPipe('dns', [], 'net');

  // Switch to scanner view if not there
  if (!document.getElementById('view-scanner').classList.contains('active')) {
    switchView('scanner');
  }

  logEvent(APP.state, 'Network recon initialized — target: ' + target);

  var seed    = hashStr(target);
  var results = {};
  var done    = [];

  // ── DNS ──
  if (document.getElementById('modDns').checked) {
    renderPipe('dns', done, 'net');
    setProgress(10, 'Resolving DNS...');
    logEvent(APP.state, 'Querying DNS records for ' + target + '...');
    await sleep(600);

    var oct1 = seededRand(seed, 220) + 20;
    var oct2 = seededRand(seed + 1, 255);
    var oct3 = seededRand(seed + 2, 255);
    var oct4 = seededRand(seed + 3, 254) + 1;

    results.dns = {
      a:     oct1 + '.' + oct2 + '.' + oct3 + '.' + oct4,
      aaaa:  '2001:db8:' + oct1.toString(16) + ':' + oct2.toString(16) + '::1',
      mx:    'mail.' + target,
      ns:    ['ns1.' + target, 'ns2.' + target],
      ttl:   [300, 3600, 86400][seededRand(seed, 3)],
    };
    logEvent(APP.state, 'A record: ' + results.dns.a, 'ok');
    done.push('dns');
  }

  // ── HEADERS ──
  if (document.getElementById('modHeaders').checked) {
    renderPipe('headers', done, 'net');
    setProgress(22, 'Analyzing HTTP headers...');
    logEvent(APP.state, 'Fetching response headers...');
    await sleep(500);

    var missing = [];
    var present = [];
    SEC_HEADERS.forEach(function(h, i) {
      if (seededRand(seed + i * 7, 10) > 4) {
        present.push(h);
      } else {
        missing.push(h);
        if (h.required) logEvent(APP.state, 'Missing: ' + h.name, 'warn');
      }
    });

    results.headers = {
      server:  ['nginx/1.24.0','Apache/2.4.57','cloudflare','Microsoft-IIS/10.0'][seededRand(seed+10, 4)],
      present: present,
      missing: missing,
      xPoweredBy: seededRand(seed+11, 3) === 0 ? 'PHP/8.1.0' : null,
    };
    done.push('headers');
  }

  // ── SSL ──
  if (document.getElementById('modSsl').checked) {
    renderPipe('ssl', done, 'net');
    setProgress(34, 'Auditing SSL/TLS configuration...');
    logEvent(APP.state, 'Checking certificate and cipher suite...');
    await sleep(550);

    var daysLeft = 30 + seededRand(seed + 20, 330);
    var expiry = new Date(Date.now() + daysLeft * 86400000);
    results.ssl = {
      valid:       true,
      issuer:      ["Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign"][seededRand(seed+21, 4)],
      subject:     '*.' + target,
      expiry:      expiry.toLocaleDateString(),
      daysLeft:    daysLeft,
      version:     ['TLS 1.2','TLS 1.3'][seededRand(seed+22, 2)],
      grade:       ['A+','A','B','C'][seededRand(seed+23, 4)],
      hsts:        seededRand(seed+24, 3) > 0,
      tlsDeprecated: seededRand(seed+25, 5) === 0,
    };

    if (daysLeft < 30) logEvent(APP.state, 'SSL cert expires in ' + daysLeft + ' days!', 'crit');
    else logEvent(APP.state, 'SSL cert valid — ' + daysLeft + ' days remaining.', 'ok');
    done.push('ssl');
  }

  // ── PORTS ──
  if (document.getElementById('modPorts').checked) {
    renderPipe('ports', done, 'net');
    setProgress(46, 'Port reconnaissance...');
    logEvent(APP.state, 'Probing common service ports...');
    await sleep(700);

    var openPorts = [];
    COMMON_PORTS.forEach(function(p, i) {
      var r = seededRand(seed + i * 13, 10);
      // Always open 80, 443; others probabilistic
      if (p.port === 80 || p.port === 443 || r < 3) {
        openPorts.push(p);
        if (p.risk === 'critical') logEvent(APP.state, 'Open: port ' + p.port + ' (' + p.svc + ') — HIGH RISK', 'crit');
        else if (p.risk === 'high') logEvent(APP.state, 'Open: port ' + p.port + ' (' + p.svc + ')', 'warn');
        else logEvent(APP.state, 'Open: port ' + p.port + ' (' + p.svc + ')', 'info');
      }
    });

    results.ports = openPorts;
    done.push('ports');
  }

  // ── WHOIS ──
  if (document.getElementById('modWhois').checked) {
    renderPipe('whois', done, 'net');
    setProgress(56, 'Querying WHOIS data...');
    logEvent(APP.state, 'Fetching registrar information...');
    await sleep(400);

    var regYear = 2000 + seededRand(seed + 30, 24);
    var expYear = new Date().getFullYear() + 1 + seededRand(seed+31, 4);
    results.whois = {
      registrar:   ['GoDaddy','Namecheap','Google Domains','Cloudflare Registrar','Network Solutions'][seededRand(seed+32, 5)],
      created:     regYear + '-' + String(seededRand(seed+33,12)+1).padStart(2,'0') + '-01',
      expires:     expYear + '-' + String(seededRand(seed+34,12)+1).padStart(2,'0') + '-01',
      nameservers: ['ns1.' + target, 'ns2.' + target],
      privacy:     seededRand(seed+35, 2) === 1,
    };
    logEvent(APP.state, 'Registrar: ' + results.whois.registrar, 'ok');
    done.push('whois');
  }

  // ── SUBDOMAINS ──
  if (document.getElementById('modSubdomains').checked) {
    renderPipe('subdomains', done, 'net');
    setProgress(66, 'Enumerating subdomains...');
    logEvent(APP.state, 'Bruteforcing common subdomain prefixes...');
    await sleep(650);

    var foundSubs = [];
    SUBDOMAIN_PREFIXES.forEach(function(pfx, i) {
      if (seededRand(seed + i * 17, 10) < 3) {
        foundSubs.push(pfx + '.' + target);
        logEvent(APP.state, 'Found subdomain: ' + pfx + '.' + target, 'info');
      }
    });

    results.subdomains = foundSubs;
    logEvent(APP.state, foundSubs.length + ' subdomains discovered.', foundSubs.length ? 'warn' : 'ok');
    done.push('subdomains');
  }

  // ── TECH STACK ──
  if (document.getElementById('modTech').checked) {
    renderPipe('tech', done, 'net');
    setProgress(76, 'Fingerprinting technology stack...');
    logEvent(APP.state, 'Analyzing headers and response patterns...');
    await sleep(450);

    var detected = [];
    TECH_STACKS.forEach(function(t, i) {
      if (seededRand(seed + i * 11, 10) < 3) {
        detected.push(t);
        logEvent(APP.state, 'Tech: ' + t.name + ' (' + t.cat + ')', 'info');
      }
    });

    results.tech = detected;
    done.push('tech');
  }

  // ── SENSITIVE FILES ──
  if (document.getElementById('modFiles').checked) {
    renderPipe('files', done, 'net');
    setProgress(86, 'Probing sensitive files...');
    logEvent(APP.state, 'Checking for exposed files and endpoints...');
    await sleep(500);

    var files = [
      { path: '/robots.txt',         risk: 'info',   found: seededRand(seed+40, 2) === 1 },
      { path: '/sitemap.xml',        risk: 'info',   found: seededRand(seed+41, 2) === 1 },
      { path: '/.env',               risk: 'critical',found: seededRand(seed+42, 8) === 1 },
      { path: '/wp-login.php',       risk: 'high',   found: seededRand(seed+43, 5) === 1 },
      { path: '/admin',              risk: 'high',   found: seededRand(seed+44, 6) === 1 },
      { path: '/phpinfo.php',        risk: 'critical',found: seededRand(seed+45, 9) === 1 },
      { path: '/wp-config.php.bak',  risk: 'critical',found: seededRand(seed+46,10) === 1 },
      { path: '/backup.sql',         risk: 'critical',found: seededRand(seed+47,12) === 1 },
      { path: '/api/v1/users',       risk: 'high',   found: seededRand(seed+48, 7) === 1 },
      { path: '/.git/config',        risk: 'critical',found: seededRand(seed+49,10) === 1 },
    ];

    files.forEach(function(f) {
      if (f.found) {
        var lvl = f.risk === 'critical' ? 'crit' : f.risk === 'high' ? 'warn' : 'ok';
        logEvent(APP.state, 'Found: ' + f.path + ' [' + f.risk.toUpperCase() + ']', lvl);
      }
    });

    results.files = files.filter(function(f) { return f.found; });
    done.push('files');
  }

  // ── COMPLETE ──
  renderPipe(null, done, 'net');
  setProgress(100, 'Recon complete');
  logEvent(APP.state, 'Network recon complete for ' + target, 'ok');
  setStatus('done', 'Recon done');

  // Build network findings for unified findings view
  var netFindings = buildNetworkFindings(target, results);
  APP.state.allFindings = netFindings;
  updateMetrics(netFindings);
  showRiskScore(netFindings);
  buildSevPills(APP.state, APP.cfg);
  renderFindings(APP.state, APP.cfg);
  buildSarif(); /* reads APP.state internally */

  // Render detailed network view and switch to show results
  renderNetworkResults(target, results);
  switchView('network');

  // Add history
  var score = computeRiskScore(netFindings);
  addHistoryEntry({
    target:   target,
    type:     'DOMAIN',
    findings: netFindings.length,
    critical: netFindings.filter(function(f) { return f.sev === 'critical'; }).length,
    high:     netFindings.filter(function(f) { return f.sev === 'high'; }).length,
    risk:     score,
    date:     new Date().toLocaleDateString(),
    time:     new Date().toLocaleTimeString(),
  });

  renderHistoryTable();
  updateDashboard(APP.state);

  if (btn) btn.disabled = false;

  /* Update findings sidebar badge */
  var badge = document.getElementById('sbFindBadge');
  if (badge) {
    badge.textContent = netFindings.length;
    badge.style.display = netFindings.length ? 'inline-flex' : 'none';
  }

  if (APP.cfg.toasts) {
    showToast('Recon complete for ' + target + '. ' + netFindings.length + ' findings.', 'success');
  }
}

/* ─────────────────────────────────────────
   IP SCAN
───────────────────────────────────────── */

async function runIpScan() {
  var ip = (document.getElementById('ipTargetInput').value || '').trim();
  if (!ip) { showToast('Enter an IP address.', 'warn'); return; }

  // Basic IP validation
  var ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRe.test(ip)) { showToast('Invalid IP address format.', 'error'); return; }

  // Set target and run as domain scan
  document.getElementById('targetInput').value = ip;
  setScanMode('domain');

  await sleep(200);
  runNetworkScan();
}

/* ─────────────────────────────────────────
   BUILD NETWORK FINDINGS
───────────────────────────────────────── */

function buildNetworkFindings(target, results) {
  var findings = [];
  var id = 0;

  function nf(opts) {
    return {
      id:          'net-' + (id++),
      type:        'NETWORK',
      title:       opts.title,
      sev:         opts.sev,
      loc:         opts.loc || target,
      line:        1,
      snippet:     opts.snippet || '',
      match:       opts.match || '',
      desc:        opts.desc,
      remediation: opts.remediation || null,
      confidence:  opts.confidence || 85,
      taint:       null,
      isNew:       false,
    };
  }

  // Headers
  if (results.headers) {
    results.headers.missing.forEach(function(h) {
      findings.push(nf({
        title: 'Missing ' + h.name,
        sev:   h.required ? 'high' : 'medium',
        match: 'Missing header',
        desc:  'The HTTP response is missing the ' + h.name + ' security header. ' +
               'This can expose users to clickjacking, content injection, or downgrade attacks.',
        remediation: {
          text: 'Add ' + h.name + ' to all HTTP responses.',
          fix:  'Header: ' + h.name + ': [recommended value]',
        },
        confidence: 98,
      }));
    });

    if (results.headers.xPoweredBy) {
      findings.push(nf({
        title: 'X-Powered-By header leaks technology',
        sev:   'low',
        desc:  'The server reveals its technology stack via X-Powered-By: ' + results.headers.xPoweredBy + '. This aids attackers in fingerprinting.',
        remediation: { text: 'Remove X-Powered-By header from responses.', fix: '' },
        confidence: 95,
      }));
    }
  }

  // SSL
  if (results.ssl) {
    if (results.ssl.daysLeft < 30) {
      findings.push(nf({
        title: 'SSL Certificate expires in ' + results.ssl.daysLeft + ' days',
        sev:   results.ssl.daysLeft < 14 ? 'critical' : 'high',
        desc:  'The SSL certificate for ' + target + ' expires on ' + results.ssl.expiry + '. Expiry will cause browser warnings and break HTTPS.',
        remediation: { text: 'Renew the certificate before expiry.', fix: '# Renew with certbot\ncertbot renew --force-renewal' },
        confidence: 99,
      }));
    }
    if (results.ssl.tlsDeprecated) {
      findings.push(nf({
        title: 'Deprecated TLS version supported',
        sev:   'high',
        desc:  'The server supports TLS 1.0 or 1.1 which are deprecated. Modern browsers block these versions.',
        remediation: { text: 'Disable TLS 1.0/1.1. Only allow TLS 1.2 and TLS 1.3.', fix: '' },
        confidence: 90,
      }));
    }
    if (!results.ssl.hsts) {
      findings.push(nf({
        title: 'HSTS not configured',
        sev:   'high',
        desc:  'HTTP Strict Transport Security is not present. Users may be vulnerable to SSL stripping attacks.',
        remediation: { text: 'Add Strict-Transport-Security header.', fix: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' },
        confidence: 95,
      }));
    }
  }

  // Ports
  if (results.ports) {
    results.ports.forEach(function(p) {
      if (p.risk === 'critical') {
        findings.push(nf({
          title: 'Port ' + p.port + ' (' + p.svc + ') open',
          sev:   'critical',
          desc:  p.svc + ' (port ' + p.port + ') is publicly accessible. This service should not be exposed to the internet.',
          remediation: { text: 'Restrict access to port ' + p.port + ' using firewall rules.', fix: 'iptables -A INPUT -p tcp --dport ' + p.port + ' -j DROP' },
          confidence: 92,
        }));
      }
    });
  }

  // Sensitive files
  if (results.files) {
    results.files.forEach(function(f) {
      if (f.risk !== 'info') {
        findings.push(nf({
          title: 'Exposed file: ' + f.path,
          sev:   f.risk,
          desc:  'The file ' + f.path + ' is publicly accessible. This may expose sensitive configuration or credentials.',
          remediation: { text: 'Block access to ' + f.path + ' via web server configuration.', fix: 'location ' + f.path + ' { deny all; }' },
          confidence: 88,
        }));
      }
    });
  }

  return sortBySeverity(findings);
}

/* ─────────────────────────────────────────
   RENDER NETWORK RESULTS
───────────────────────────────────────── */

function renderNetworkResults(target, results) {
  var container = document.getElementById('networkResults');
  if (!container) return;

  var html = '<div class="network-grid">';

  // DNS card
  if (results.dns) {
    html += '<div class="net-card">';
    html += '<div class="net-card-head"><div class="nc-dot ok"></div>DNS RECORDS</div>';
    html += '<div class="net-card-body">';
    html += netRow('A Record', results.dns.a);
    html += netRow('AAAA Record', results.dns.aaaa);
    html += netRow('MX Record', results.dns.mx);
    html += netRow('Nameservers', results.dns.ns.join(', '));
    html += netRow('TTL', results.dns.ttl + 's');
    html += '</div></div>';
  }

  // SSL card
  if (results.ssl) {
    var sslDot = results.ssl.daysLeft < 30 ? 'bad' : results.ssl.tlsDeprecated ? 'warn' : 'ok';
    var gradeColor = { 'A+': 'ok', 'A': 'ok', 'B': 'warn', 'C': 'bad' }[results.ssl.grade] || 'info';
    html += '<div class="net-card">';
    html += '<div class="net-card-head"><div class="nc-dot ' + sslDot + '"></div>SSL/TLS</div>';
    html += '<div class="net-card-body">';
    html += netRow('Grade', '<span class="nr-val ' + gradeColor + '">' + results.ssl.grade + '</span>');
    html += netRow('Version', results.ssl.version);
    html += netRow('Issuer', results.ssl.issuer);
    html += netRow('Subject', results.ssl.subject);
    html += netRow('Expires', results.ssl.expiry + ' (' + results.ssl.daysLeft + ' days)');
    html += netRow('HSTS', results.ssl.hsts
      ? '<span class="net-tag present">ENABLED</span>'
      : '<span class="net-tag missing">MISSING</span>');
    html += netRow('TLS 1.0/1.1', results.ssl.tlsDeprecated
      ? '<span class="net-tag missing">ENABLED (deprecated)</span>'
      : '<span class="net-tag present">DISABLED</span>');
    html += '</div></div>';
  }

  // Headers card
  if (results.headers) {
    var missingCrit = results.headers.missing.filter(function(h) { return h.required; }).length;
    html += '<div class="net-card">';
    html += '<div class="net-card-head"><div class="nc-dot ' + (missingCrit > 0 ? 'warn' : 'ok') + '"></div>SECURITY HEADERS</div>';
    html += '<div class="net-card-body">';
    html += netRow('Server', results.headers.server);
    html += '<div class="net-row"><span class="nr-key">Headers:</span><span class="nr-val">';
    results.headers.present.forEach(function(h) {
      html += '<span class="net-tag present">' + escHtml(h.short) + '</span>';
    });
    results.headers.missing.forEach(function(h) {
      html += '<span class="net-tag missing">No ' + escHtml(h.short) + '</span>';
    });
    html += '</span></div>';
    html += netRow('X-Powered-By', results.headers.xPoweredBy
      ? '<span class="nr-val warn">' + escHtml(results.headers.xPoweredBy) + '</span>'
      : '<span class="nr-val ok">Hidden</span>');
    html += '</div></div>';
  }

  // Ports card
  if (results.ports && results.ports.length) {
    var critPorts = results.ports.filter(function(p) { return p.risk === 'critical'; }).length;
    html += '<div class="net-card">';
    html += '<div class="net-card-head"><div class="nc-dot ' + (critPorts ? 'bad' : 'warn') + '"></div>OPEN PORTS</div>';
    html += '<div class="port-grid">';
    results.ports.forEach(function(p) {
      var cls = p.risk === 'critical' ? 'open' : p.risk === 'high' || p.risk === 'medium' ? 'filtered' : 'closed';
      html += '<div class="port-badge ' + cls + '">' + p.port + ' ' + p.svc + '</div>';
    });
    html += '</div></div>';
  }

  // WHOIS card
  if (results.whois) {
    html += '<div class="net-card">';
    html += '<div class="net-card-head"><div class="nc-dot info"></div>WHOIS</div>';
    html += '<div class="net-card-body">';
    html += netRow('Registrar', results.whois.registrar);
    html += netRow('Created', results.whois.created);
    html += netRow('Expires', results.whois.expires);
    html += netRow('Privacy', results.whois.privacy
      ? '<span class="net-tag present">ENABLED</span>'
      : '<span class="net-tag missing">DISABLED</span>');
    html += '</div></div>';
  }

  // Subdomains card
  if (results.subdomains) {
    html += '<div class="net-card">';
    html += '<div class="net-card-head"><div class="nc-dot ' + (results.subdomains.length ? 'warn' : 'ok') + '"></div>SUBDOMAINS (' + results.subdomains.length + ')</div>';
    html += '<div class="net-card-body">';
    if (results.subdomains.length) {
      results.subdomains.forEach(function(sub) {
        html += '<div class="net-row"><span class="nr-val"><span class="net-tag neutral">' + escHtml(sub) + '</span></span></div>';
      });
    } else {
      html += '<div class="net-row"><span class="nr-val" style="color:var(--text2)">No subdomains found.</span></div>';
    }
    html += '</div></div>';
  }

  // Tech stack card
  if (results.tech && results.tech.length) {
    html += '<div class="net-card">';
    html += '<div class="net-card-head"><div class="nc-dot info"></div>TECH STACK</div>';
    html += '<div class="net-card-body">';
    results.tech.forEach(function(t) {
      html += netRow(t.cat, '<span class="net-tag ' + (t.risk === 'warn' ? 'warn' : 'neutral') + '">' + escHtml(t.name) + '</span>');
    });
    html += '</div></div>';
  }

  // Sensitive files card
  if (results.files && results.files.length) {
    html += '<div class="net-card">';
    html += '<div class="net-card-head"><div class="nc-dot bad"></div>EXPOSED FILES (' + results.files.length + ')</div>';
    html += '<div class="net-card-body">';
    results.files.forEach(function(f) {
      var cls = f.risk === 'critical' ? 'missing' : f.risk === 'high' ? 'warn' : 'neutral';
      html += '<div class="net-row"><span class="nr-key">' + escHtml(f.path) + '</span>' +
              '<span class="net-tag ' + cls + '">' + f.risk.toUpperCase() + '</span></div>';
    });
    html += '</div></div>';
  }

  html += '</div>';
  container.innerHTML = html;
}

function netRow(key, val) {
  return '<div class="net-row"><span class="nr-key">' + escHtml(key) + '</span>' +
         '<span class="nr-val">' + val + '</span></div>';
}

function setTarget(val) {
  var el = document.getElementById('targetInput');
  if (el) el.value = val;
}

function setIpTarget(val) {
  var el = document.getElementById('ipTargetInput');
  if (el) el.value = val;
}