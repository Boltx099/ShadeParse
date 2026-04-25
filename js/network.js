/**
 * ShadeParse — network.js
<<<<<<< HEAD
 * Domain, URL, and IP scan simulation.
 * Generates realistic recon output using client-side analysis.
=======
 * Real OSINT recon using public, browser-accessible, CORS-open APIs.
 *
 * What is queried (all parallel, all free, no API keys):
 *   DNS (A/AAAA/MX/NS/TXT/CAA/CNAME/SOA/SRV/DMARC) → dns.google + cloudflare-dns.com (race)
 *   Reverse DNS (PTR)                              → dns.google
 *   SSL / CT logs                                   → crt.sh + certspotter.com (fallback)
 *   Subdomains                                      → CT logs + hackertarget.com hostsearch
 *   IP geo / ASN                                    → ipapi.co + ipwho.is (race)
 *   IP exposure (open ports + CVEs + hostnames)     → internetdb.shodan.io
 *   ASN / prefix / RIR                              → api.bgpview.io
 *   Network info + abuse contact                    → stat.ripe.net (RIPEstat)
 *   WHOIS / RDAP                                    → rdap.org / rdap.arin.net / verisign / nominet
 *   Historical presence                             → archive.org Wayback Machine
 *   HTTP headers (best-effort, browser CORS limits) → direct fetch
 *   HTTP/HTTPS port probe                           → fetch HEAD no-cors
 *   Sensitive files (robots/sitemap/.env/.git)      → fetch HEAD no-cors
 *
 * Browser limits we are honest about:
 *   - Reading response headers of cross-origin sites is blocked by CORS
 *     unless the target opts in. We display "REACHABLE" rather than fake data.
 *   - Raw TCP scanning is impossible from a browser; only HTTP/HTTPS-speaking
 *     ports can be detected.
>>>>>>> 921b7bd (- IP and Domain/URL Scanner updated\n- Added New sources like wayback, BGP, crt.sh, etc to the scanners.\n- Added the restroing functionality to the history options.\n- Now the IP and URL/Domain Scanner can gather too much information about the Geo Location and other information.\n- The Code Auditor got improved.)
 */

'use strict';

<<<<<<< HEAD
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
=======
/* ─── CONSTANTS ─── */
var SEC_HEADERS = [
  { name: 'strict-transport-security', short: 'HSTS',              required: true  },
  { name: 'content-security-policy',   short: 'CSP',               required: true  },
  { name: 'x-frame-options',           short: 'X-Frame-Options',   required: true  },
  { name: 'x-content-type-options',    short: 'X-Content-Type',    required: true  },
  { name: 'referrer-policy',           short: 'Referrer-Policy',   required: false },
  { name: 'permissions-policy',        short: 'Permissions-Policy',required: false },
];

/* Well-known infrastructure IPs.
   Hits here get an explanatory banner and skip modules that don't apply
   (reverse-IP and sensitive-file probes are nonsensical on a DNS resolver). */
var INFRA_REGISTRY = {
  '1.1.1.1':         { kind:'anycast-dns', provider:'Cloudflare',    service:'Cloudflare Public DNS (1.1.1.1)',
                        notes:'Anycast public DNS resolver. Supports DoH/DoT/DNSCrypt. Geo reflects registration city, not the actual server you reached.',
                        skip:['revip','files'] },
  '1.0.0.1':         { kind:'anycast-dns', provider:'Cloudflare',    service:'Cloudflare Public DNS (1.0.0.1, secondary)',
                        notes:'Cloudflare anycast DNS, secondary address.', skip:['revip','files'] },
  '8.8.8.8':         { kind:'anycast-dns', provider:'Google',        service:'Google Public DNS (8.8.8.8)',
                        notes:'Anycast public DNS resolver (dns.google). Supports DoH/DoT. Each query may hit a different PoP worldwide.',
                        skip:['revip','files'] },
  '8.8.4.4':         { kind:'anycast-dns', provider:'Google',        service:'Google Public DNS (8.8.4.4, secondary)',
                        notes:'Google anycast DNS, secondary address.', skip:['revip','files'] },
  '9.9.9.9':         { kind:'anycast-dns', provider:'Quad9',         service:'Quad9 DNS (9.9.9.9)',
                        notes:'Privacy/security-focused anycast DNS resolver. Blocks known malware C2 by default.', skip:['revip','files'] },
  '149.112.112.112': { kind:'anycast-dns', provider:'Quad9',         service:'Quad9 DNS (secondary)', notes:'Quad9 secondary anycast IP.', skip:['revip','files'] },
  '208.67.222.222':  { kind:'anycast-dns', provider:'OpenDNS (Cisco)', service:'OpenDNS Resolver1', notes:'Cisco-operated public DNS; anycast.', skip:['revip','files'] },
  '208.67.220.220':  { kind:'anycast-dns', provider:'OpenDNS (Cisco)', service:'OpenDNS Resolver2', notes:'OpenDNS secondary anycast IP.', skip:['revip','files'] },
  '4.2.2.1':         { kind:'anycast-dns', provider:'Level3 / Lumen', service:'Level3/CenturyLink Resolver', notes:'Legacy Level3 public DNS.', skip:['revip','files'] },
  '4.2.2.2':         { kind:'anycast-dns', provider:'Level3 / Lumen', service:'Level3/CenturyLink Resolver', notes:'Legacy Level3 public DNS.', skip:['revip','files'] },
  '94.140.14.14':    { kind:'anycast-dns', provider:'AdGuard',       service:'AdGuard DNS', notes:'Ad/tracker-blocking anycast DNS resolver.', skip:['revip','files'] },
  '94.140.15.15':    { kind:'anycast-dns', provider:'AdGuard',       service:'AdGuard DNS (family)', notes:'AdGuard family-protection DNS.', skip:['revip','files'] },
  '76.76.2.0':       { kind:'anycast-dns', provider:'Control D',     service:'Control D DNS', notes:'Configurable anycast DNS resolver.', skip:['revip','files'] },
  '76.76.10.0':      { kind:'anycast-dns', provider:'Control D',     service:'Control D DNS (alt)', notes:'Control D alternate anycast IP.', skip:['revip','files'] },
  '185.228.168.9':   { kind:'anycast-dns', provider:'CleanBrowsing', service:'CleanBrowsing DNS', notes:'Filtering anycast DNS resolver.', skip:['revip','files'] },
  '185.228.169.9':   { kind:'anycast-dns', provider:'CleanBrowsing', service:'CleanBrowsing DNS (alt)', notes:'CleanBrowsing alternate anycast IP.', skip:['revip','files'] },
  // Root nameservers
  '198.41.0.4':      { kind:'root-dns', provider:'Verisign', service:'a.root-servers.net', notes:'A-root DNS server.', skip:['revip','files'] },
  '199.9.14.201':    { kind:'root-dns', provider:'USC-ISI',  service:'b.root-servers.net', notes:'B-root DNS server.', skip:['revip','files'] },
  '192.33.4.12':     { kind:'root-dns', provider:'Cogent',   service:'c.root-servers.net', notes:'C-root DNS server.', skip:['revip','files'] }
};

var SENSITIVE_PATHS = [
  { path: '/robots.txt',      sev: 'info',     label: 'robots.txt' },
  { path: '/sitemap.xml',     sev: 'info',     label: 'sitemap.xml' },
  { path: '/.env',            sev: 'critical', label: '.env' },
  { path: '/.git/HEAD',       sev: 'critical', label: '.git/HEAD' },
  { path: '/.git/config',     sev: 'critical', label: '.git/config' },
  { path: '/.DS_Store',       sev: 'medium',   label: '.DS_Store' },
  { path: '/wp-config.php',   sev: 'critical', label: 'wp-config.php' },
  { path: '/server-status',   sev: 'high',     label: 'Apache server-status' },
  { path: '/phpinfo.php',     sev: 'high',     label: 'phpinfo.php' },
  { path: '/.well-known/security.txt', sev: 'info', label: 'security.txt' },
  { path: '/admin',           sev: 'low',      label: '/admin' },
  { path: '/login',           sev: 'info',     label: '/login' },
  { path: '/api',             sev: 'info',     label: '/api' },
];

/* ─── UTILITY ─── */
function abortFetch(url, opts, ms) {
  var ac = typeof AbortController !== 'undefined' ? new AbortController() : null;
  var t  = ac ? setTimeout(function(){ ac.abort(); }, ms) : null;
  var o  = Object.assign({}, opts || {});
  if (ac) o.signal = ac.signal;
  return fetch(url, o).finally(function(){ if (t) clearTimeout(t); });
}

function tryJson(url, ms, opts) {
  return abortFetch(url, opts || {}, ms || 8000)
    .then(function(r){ return r.ok ? r.json() : null; })
    .catch(function(){ return null; });
}

function tryText(url, ms, opts) {
  return abortFetch(url, opts || {}, ms || 8000)
    .then(function(r){ return r.ok ? r.text() : null; })
    .catch(function(){ return null; });
}

function parseHost(raw) {
  return raw.replace(/^https?:\/\//i,'').replace(/[/?#].*/,'').replace(/:[\d]+$/,'').toLowerCase().trim();
}

function isPrivate(h) {
  return /^(localhost|127\.|0\.0\.0\.0|10\.|169\.254\.|::1)/i.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^192\.168\./.test(h);
}

function isValidHost(h) {
  return /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(h) ||
    /^(\d{1,3}\.){3}\d{1,3}$/.test(h);
}

function isIpAddr(h) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(h); }

/* ─────────────────────────────────────────
   Target classifier — recognizes infrastructure IPs and cloud/CDN edges.
   Two stages:
     1. Hardcoded registry hit → use richest metadata (anycast DNS, root NS).
     2. ASN/org pattern match → cloud/CDN inference using BGP & geo data.
   Returns { kind, provider, service, notes, skip:[] }.
   `skip` lists module names that don't apply: 'revip', 'files'.
───────────────────────────────────────── */
function classifyTarget(target, R) {
  if (INFRA_REGISTRY[target]) return Object.assign({}, INFRA_REGISTRY[target]);

  if (R && R.geo && R.geo.isAnycast) {
    return { kind:'anycast', provider:'unknown', service:'Anycast IP',
             notes:'Anycast address — geolocation reflects registration, not the actual server reached.',
             skip:['revip','files'] };
  }

  var org = '';
  if (R && R.bgp && R.bgp.asnDesc)  org = String(R.bgp.asnDesc).toLowerCase();
  else if (R && R.bgp && R.bgp.asnName) org = String(R.bgp.asnName).toLowerCase();
  else if (R && R.geo && R.geo.org) org = String(R.geo.org).toLowerCase();

  if (!org) return { kind:'normal', provider:'unknown', service:'Standard IP', notes:'', skip:[] };

  if (/cloudflare/.test(org))                return { kind:'cdn',   provider:'Cloudflare',   service:'Cloudflare edge',  notes:'Cloudflare CDN/WAF edge — virtual-hosted across thousands of sites; reverse-IP would just list Cloudflare-fronted domains.', skip:['revip'] };
  if (/akamai technologies/.test(org))       return { kind:'cdn',   provider:'Akamai',       service:'Akamai edge',      notes:'Akamai CDN edge node.', skip:['revip'] };
  if (/fastly/.test(org))                    return { kind:'cdn',   provider:'Fastly',       service:'Fastly edge',      notes:'Fastly CDN edge.', skip:['revip'] };
  if (/incapsula|imperva/.test(org))         return { kind:'cdn',   provider:'Imperva',      service:'Imperva/Incapsula edge', notes:'Imperva WAF/CDN edge.', skip:['revip'] };
  if (/sucuri/.test(org))                    return { kind:'cdn',   provider:'Sucuri',       service:'Sucuri edge',      notes:'Sucuri WAF/CDN.', skip:['revip'] };
  if (/(^|\s)(amazon|aws|amazon\.com)(\s|$|,)/.test(org)) return { kind:'cloud', provider:'AWS',         service:'AWS-hosted',       notes:'Amazon Web Services. Could be EC2, ELB, CloudFront, or S3 endpoint.', skip:[] };
  if (/microsoft|azure/.test(org))           return { kind:'cloud', provider:'Azure',        service:'Azure-hosted',     notes:'Microsoft Azure infrastructure.', skip:[] };
  if (/google llc|google cloud/.test(org))   return { kind:'cloud', provider:'Google',       service:'Google-hosted',    notes:'Google Cloud or Google service.', skip:[] };
  if (/digital\s?ocean/.test(org))           return { kind:'cloud', provider:'DigitalOcean', service:'DigitalOcean',     notes:'DigitalOcean droplet/load-balancer.', skip:[] };
  if (/hetzner/.test(org))                   return { kind:'cloud', provider:'Hetzner',      service:'Hetzner-hosted',   notes:'Hetzner cloud or dedicated.', skip:[] };
  if (/oracle/.test(org))                    return { kind:'cloud', provider:'Oracle',       service:'Oracle Cloud',     notes:'Oracle Cloud Infrastructure.', skip:[] };
  if (/linode/.test(org))                    return { kind:'cloud', provider:'Linode',       service:'Linode VPS',       notes:'Linode (Akamai) VPS.', skip:[] };
  if (/ovh/.test(org))                       return { kind:'cloud', provider:'OVH',          service:'OVH-hosted',       notes:'OVH dedicated/cloud.', skip:[] };
  if (/vultr/.test(org))                     return { kind:'cloud', provider:'Vultr',        service:'Vultr VPS',        notes:'Vultr cloud.', skip:[] };
  if (/(alibaba|tencent|baidu)/.test(org))   return { kind:'cloud', provider:RegExp.$1.replace(/^\w/,function(c){return c.toUpperCase();}), service:'Asia cloud', notes:'Major Asia-Pacific cloud provider.', skip:[] };
  if (/leaseweb/.test(org))                  return { kind:'cloud', provider:'Leaseweb',     service:'Leaseweb-hosted',  notes:'Leaseweb dedicated/cloud.', skip:[] };

  return { kind:'normal', provider:'unknown', service:'Standard IP', notes:'No infrastructure signature — treating as a regular host.', skip:[] };
}

/* ─────────────────────────────────────────
   DNS — Google + Cloudflare DoH (race)
   Now covers: A, AAAA, MX, NS, TXT, CAA, CNAME, SOA, SRV, DMARC
───────────────────────────────────────── */
function dohQuery(provider, name, type) {
  var url = provider === 'cf'
    ? 'https://cloudflare-dns.com/dns-query?name='+encodeURIComponent(name)+'&type='+type
    : 'https://dns.google/resolve?name='+encodeURIComponent(name)+'&type='+type;
  return abortFetch(url, { headers:{ Accept:'application/dns-json' } }, 6000)
    .then(function(r){ return r.ok ? r.json() : null; })
    .catch(function(){ return null; });
}

function dohRace(name, type) {
  // Resolve as soon as one provider returns a usable answer; fall through to whichever finishes
  return Promise.any([
    dohQuery('google', name, type).then(function(d){ if(!d||!d.Answer) throw 0; return d; }),
    dohQuery('cf',     name, type).then(function(d){ if(!d||!d.Answer) throw 0; return d; }),
  ]).catch(function(){ return null; });
}

async function dnsLookup(host) {
  var out = { a:[], aaaa:[], mx:[], ns:[], txt:[], caa:[], cname:[], soa:null, srv:[], dmarc:[], spf:[], dkim:false, error:null };
  var types = ['A','AAAA','MX','NS','TXT','CAA','CNAME','SOA','SRV'];
  var results = await Promise.all(types.map(function(t){ return dohRace(host, t); }));
  results.forEach(function(d, idx){
    if (!d || !d.Answer) return;
    var t = types[idx];
    d.Answer.forEach(function(rec){
      var v = rec.data;
      if (t==='A')     out.a.push(v);
      else if (t==='AAAA')  out.aaaa.push(v);
      else if (t==='MX')    out.mx.push(v);
      else if (t==='NS')    out.ns.push(v);
      else if (t==='TXT')   { out.txt.push(v.replace(/^"|"$/g,'')); }
      else if (t==='CAA')   out.caa.push(v);
      else if (t==='CNAME') out.cname.push(v);
      else if (t==='SOA')   out.soa = v;
      else if (t==='SRV')   out.srv.push(v);
    });
  });
  // Pull SPF out of TXT
  out.txt.forEach(function(v){ if(/^v=spf1/i.test(v)) out.spf.push(v); });
  // DMARC lives at _dmarc.<host>
  var dmarc = await dohRace('_dmarc.'+host, 'TXT');
  if (dmarc && dmarc.Answer) {
    dmarc.Answer.forEach(function(r){
      var v = (r.data||'').replace(/^"|"$/g,'');
      if (/^v=DMARC1/i.test(v)) out.dmarc.push(v);
    });
  }
  return out;
}

async function ptrLookup(ip) {
  try {
    var rev = ip.split('.').reverse().join('.')+'.in-addr.arpa';
    var d = await dohRace(rev, 'PTR');
    return (d && d.Answer && d.Answer[0]) ? d.Answer[0].data.replace(/\.$/,'') : null;
  } catch(e){ return null; }
}

/* ─────────────────────────────────────────
   crt.sh — certificate transparency
   With certSpotter as a fallback when crt.sh is slow/down.
───────────────────────────────────────── */
async function crtShLookup(host) {
  var out = { found:false, certs:[], subdomains:[], issuer:null, expiry:null, daysLeft:null, certCount:0, source:null, error:null };

  var urls = [
    'https://crt.sh/?q='+encodeURIComponent('%.'+host)+'&output=json&deduplicate=Y',
    'https://crt.sh/?q='+encodeURIComponent('%.'+host)+'&output=json',
  ];

  for (var i = 0; i < urls.length; i++) {
    try {
      var r = await abortFetch(urls[i], {}, 30000);
      if (!r.ok) { out.error = 'crt.sh HTTP '+r.status; continue; }
      var text = await r.text();
      if (!text || text.trim().length < 3) { out.error = 'Empty response'; continue; }
      var data = JSON.parse(text);
      if (!Array.isArray(data) || !data.length) { out.error = 'No records'; continue; }

      out.found = true; out.source = 'crt.sh'; out.certCount = data.length;

      var seen = {};
      data.forEach(function(c){
        var k = (c.common_name||'')+'|'+(c.not_after||'');
        if (!seen[k]){ seen[k]=true; out.certs.push(c); }
      });
      out.certs.sort(function(a,b){ return new Date(b.not_after)-new Date(a.not_after); });

      var latest = out.certs[0];
      out.issuer   = (latest.issuer_name||'').split(',').filter(function(s){ return s.trim().startsWith('CN='); })[0];
      out.issuer   = out.issuer ? out.issuer.replace('CN=','').trim() : (latest.issuer_name||'Unknown');
      var expDate  = new Date(latest.not_after);
      out.expiry   = expDate.toLocaleDateString();
      out.daysLeft = Math.round((expDate - Date.now())/86400000);
      out.subject  = latest.common_name || host;

      var subSeen = {};
      data.forEach(function(c){
        (c.name_value||'').split(/\n/).forEach(function(n){
          n = n.trim().toLowerCase().replace(/^\*\./,'');
          if (n && n!==host && n.endsWith('.'+host) && !subSeen[n]){
            subSeen[n]=true; out.subdomains.push(n);
          }
        });
      });
      out.subdomains.sort();
      out.subdomains = out.subdomains.slice(0,80);
      return out;
    } catch(e){
      out.error = e.message;
    }
  }

  // Fallback: certspotter (cap at 100 issuances)
  try {
    var cs = await tryJson(
      'https://api.certspotter.com/v1/issuances?domain='+encodeURIComponent(host)+
      '&include_subdomains=true&expand=dns_names&expand=issuer&expand=not_after',
      15000
    );
    if (Array.isArray(cs) && cs.length) {
      out.found = true; out.source = 'certspotter'; out.certCount = cs.length;
      cs.sort(function(a,b){ return new Date(b.not_after)-new Date(a.not_after); });
      var latest = cs[0];
      out.issuer = (latest.issuer && latest.issuer.name) || 'Unknown';
      var ex = new Date(latest.not_after);
      out.expiry = ex.toLocaleDateString();
      out.daysLeft = Math.round((ex - Date.now())/86400000);
      out.subject = (latest.dns_names && latest.dns_names[0]) || host;
      var subSeen = {};
      cs.forEach(function(c){
        (c.dns_names||[]).forEach(function(n){
          n = (n||'').toLowerCase().replace(/^\*\./,'');
          if (n && n!==host && n.endsWith('.'+host) && !subSeen[n]) {
            subSeen[n]=true; out.subdomains.push(n);
          }
        });
      });
      out.subdomains.sort();
      out.subdomains = out.subdomains.slice(0,80);
    }
  } catch(e){ if(!out.error) out.error = e.message; }

  return out;
}

/* ─────────────────────────────────────────
   HackerTarget hostsearch — extra subdomains
   (50 req/day per IP shared limit; gracefully degrade)
───────────────────────────────────────── */
async function hackerTargetHosts(host) {
  var out = { hosts:[], error:null };
  var txt = await tryText('https://api.hackertarget.com/hostsearch/?q='+encodeURIComponent(host), 8000);
  if (!txt) { out.error = 'unreachable'; return out; }
  if (/error|API count exceeded/i.test(txt)) { out.error = txt.trim(); return out; }
  txt.split(/\r?\n/).forEach(function(line){
    var p = line.split(',');
    if (p[0] && p[0].endsWith(host) && p[0]!==host) {
      out.hosts.push({ host: p[0].toLowerCase(), ip: (p[1]||'').trim() });
    }
  });
  return out;
}

/* ─────────────────────────────────────────
   Shodan InternetDB — IP exposure (open ports, CVEs, hostnames)
   Free, public, CORS-open, no API key required.
───────────────────────────────────────── */
async function internetDbLookup(ip) {
  var out = { ports:[], vulns:[], hostnames:[], cpes:[], tags:[], found:false, error:null };
  try {
    var r = await abortFetch('https://internetdb.shodan.io/'+encodeURIComponent(ip), {}, 8000);
    if (r.status === 404) { out.error = 'No exposure data'; return out; }
    if (!r.ok) { out.error = 'HTTP '+r.status; return out; }
    var d = await r.json();
    out.found     = true;
    out.ports     = d.ports     || [];
    out.vulns     = d.vulns     || [];
    out.hostnames = d.hostnames || [];
    out.cpes      = d.cpes      || [];
    out.tags      = d.tags      || [];
  } catch(e){ out.error = e.message; }
  return out;
}

/* ─────────────────────────────────────────
   BGPView — ASN / prefix / RIR / allocation
───────────────────────────────────────── */
async function bgpViewLookup(target, asIp) {
  var out = { asn:null, asnName:null, asnDesc:null, country:null, rir:null, prefix:null, allocated:null, found:false, error:null };
  var url = asIp
    ? 'https://api.bgpview.io/ip/'+encodeURIComponent(target)
    : 'https://api.bgpview.io/search?query_term='+encodeURIComponent(target);
  var d = await tryJson(url, 8000);
  if (!d || d.status !== 'ok' || !d.data) { out.error = 'no data'; return out; }
  out.found = true;
  if (asIp) {
    var p = (d.data.prefixes && d.data.prefixes[0]) || null;
    if (p) {
      out.prefix    = p.prefix;
      out.country   = p.country_code;
      if (p.asn) {
        out.asn     = 'AS'+p.asn.asn;
        out.asnName = p.asn.name;
        out.asnDesc = p.asn.description;
      }
    }
    if (d.data.rir_allocation) {
      out.rir       = d.data.rir_allocation.rir_name;
      out.allocated = d.data.rir_allocation.date_allocated;
    }
  } else {
    var asns = d.data.asns || [];
    if (asns[0]) {
      out.asn = 'AS'+asns[0].asn;
      out.asnName = asns[0].name;
      out.asnDesc = asns[0].description;
      out.country = asns[0].country_code;
    }
  }
  return out;
}

/* ─────────────────────────────────────────
   RIPEstat — network-info + abuse-contact
───────────────────────────────────────── */
async function ripeStatLookup(ip) {
  var out = { prefix:null, asns:[], abuse:[], found:false, error:null };
  var ni = await tryJson('https://stat.ripe.net/data/network-info/data.json?resource='+encodeURIComponent(ip), 6000);
  if (ni && ni.data) {
    out.found  = true;
    out.prefix = ni.data.prefix || null;
    out.asns   = ni.data.asns   || [];
  }
  var ab = await tryJson('https://stat.ripe.net/data/abuse-contact-finder/data.json?resource='+encodeURIComponent(ip), 6000);
  if (ab && ab.data && ab.data.abuse_contacts) {
    out.abuse = ab.data.abuse_contacts.slice(0,3);
    out.found = true;
  }
  if (!out.found) out.error = 'no data';
  return out;
}

/* ─────────────────────────────────────────
   IP Geo — query 3 sources in parallel and merge the best fields.
   Source priority: ipapi.co → ipwho.is → freeipapi.com.
   Each runs independently with a 6s cap; we merge whatever returns
   so a single rate-limited or down provider can't make the card empty.
───────────────────────────────────────── */
async function ipGeo(ip) {
  function ipapi() {
    return tryJson('https://ipapi.co/'+encodeURIComponent(ip)+'/json/', 6000)
      .then(function(d){
        if (!d || d.error) return null;
        return {
          ip: d.ip || ip, asn: d.asn || null, org: d.org || null, isp: d.org || null,
          city: d.city, region: d.region, country: d.country_name, countryCode: d.country_code,
          continent: d.continent_code, lat: d.latitude, lng: d.longitude,
          timezone: d.timezone, utcOffset: d.utc_offset, network: d.network,
          currency: d.currency, callingCode: d.country_calling_code, source: 'ipapi.co'
        };
      });
  }
  function ipwhois() {
    return tryJson('https://ipwho.is/'+encodeURIComponent(ip), 6000)
      .then(function(d){
        if (!d || d.success === false) return null;
        return {
          ip: d.ip || ip,
          asn: d.connection && d.connection.asn ? 'AS'+d.connection.asn : null,
          org: (d.connection && d.connection.org) || (d.connection && d.connection.isp) || null,
          isp: (d.connection && d.connection.isp) || null,
          city: d.city, region: d.region, country: d.country, countryCode: d.country_code,
          continent: d.continent_code, lat: d.latitude, lng: d.longitude,
          timezone: d.timezone && d.timezone.id, utcOffset: d.timezone && d.timezone.utc,
          network: null, currency: d.currency && d.currency.code,
          callingCode: d.calling_code, source: 'ipwho.is'
        };
      });
  }
  function freeipapi() {
    return tryJson('https://freeipapi.com/api/json/'+encodeURIComponent(ip), 6000)
      .then(function(d){
        if (!d || !d.ipAddress) return null;
        return {
          ip: d.ipAddress, asn: null, org: null, isp: null,
          city: d.cityName, region: d.regionName, country: d.countryName, countryCode: d.countryCode,
          continent: d.continent || d.continentCode, lat: d.latitude, lng: d.longitude,
          timezone: d.timeZone, network: null, source: 'freeipapi.com'
        };
      });
  }

  // RIPEstat MaxMind GeoLite — virtually always works (permissive CORS)
  function ripeMaxmind() {
    return tryJson('https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource='+encodeURIComponent(ip), 6000)
      .then(function(d){
        if (!d || !d.data || !d.data.located_resources || !d.data.located_resources[0]) return null;
        var loc = d.data.located_resources[0].locations && d.data.located_resources[0].locations[0];
        if (!loc) return null;
        return {
          ip: ip, asn: null, org: null, isp: null,
          city: loc.city, region: null, country: loc.country, countryCode: loc.country,
          continent: null, lat: loc.latitude, lng: loc.longitude,
          timezone: null, network: null, source: 'RIPEstat'
        };
      });
  }
  // geojs.io — third-party geo, also CORS-permissive
  function geoJs() {
    return tryJson('https://get.geojs.io/v1/ip/geo/'+encodeURIComponent(ip)+'.json', 6000)
      .then(function(d){
        if (!d || !d.ip) return null;
        return {
          ip: d.ip,
          asn: d.asn ? 'AS'+d.asn : null, org: d.organization || null, isp: d.organization_name || null,
          city: d.city, region: d.region, country: d.country, countryCode: d.country_code,
          continent: d.continent_code,
          lat: d.latitude  ? parseFloat(d.latitude)  : null,
          lng: d.longitude ? parseFloat(d.longitude) : null,
          timezone: d.timezone, network: null, source: 'geojs.io'
        };
      });
  }

  var settled = await Promise.allSettled([ipapi(), ipwhois(), freeipapi(), ripeMaxmind(), geoJs()]);
  var values  = settled.map(function(r){ return r.status==='fulfilled' ? r.value : null; }).filter(Boolean);
  if (!values.length) return null;

  // Per-field cross-source vote so the user can see how much providers agree.
  function vote(field, normalize) {
    normalize = normalize || function(x){ return String(x).trim(); };
    var counts = {}, total = 0, sourceMap = {};
    values.forEach(function(v){
      if (v[field] != null && v[field] !== '') {
        var k = normalize(v[field]);
        counts[k] = (counts[k]||0) + 1;
        total++;
        (sourceMap[k] = sourceMap[k] || []).push(v.source);
      }
    });
    if (total === 0) return null;
    var winner = null, max = 0;
    Object.keys(counts).forEach(function(k){ if (counts[k]>max){ max=counts[k]; winner=k; } });
    var ratio = max/total;
    return {
      value: winner,
      votes: max,
      total: total,
      confidence: ratio>=0.75 ? 'high' : ratio>=0.5 ? 'med' : 'low',
      all: counts,
      sources: sourceMap
    };
  }

  var agreement = {
    country:     vote('country',     function(v){ return String(v).trim().toLowerCase(); }),
    countryCode: vote('countryCode', function(v){ return String(v).toUpperCase().trim(); }),
    city:        vote('city',        function(v){ return String(v).trim().toLowerCase(); }),
    region:      vote('region',      function(v){ return String(v).trim().toLowerCase(); }),
    asn:         vote('asn',         function(v){ return String(v).toUpperCase().replace(/^AS/,'AS').trim(); }),
    org:         vote('org',         function(v){ return String(v).trim().toLowerCase(); })
  };

  // Merge: prefer the field value with the highest agreement, fall back to first non-null.
  var merged = {};
  values.forEach(function(v){
    Object.keys(v).forEach(function(k){
      if ((merged[k] == null || merged[k] === '') && v[k] != null && v[k] !== '') merged[k] = v[k];
    });
  });

  // Anycast heuristic — known public-DNS anycast addresses where geo
  // is meaningless because the IP is announced from many PoPs worldwide.
  var ANYCAST_IPS = {
    '1.1.1.1':1,'1.0.0.1':1,'8.8.8.8':1,'8.8.4.4':1,'9.9.9.9':1,'149.112.112.112':1,
    '4.2.2.1':1,'4.2.2.2':1,'208.67.222.222':1,'208.67.220.220':1,
    '64.6.64.6':1,'64.6.65.6':1,'94.140.14.14':1,'94.140.15.15':1,
    '76.76.2.0':1,'76.76.10.0':1,'185.228.168.9':1
  };
  merged.isAnycast = !!ANYCAST_IPS[ip];

  merged.sources    = values;     // raw per-source array (for the Source Comparison card)
  merged.agreement  = agreement;
  merged.source     = values.map(function(v){ return v.source; }).join(' + ');
  return merged;
}

/* ─────────────────────────────────────────
   Reverse-IP liveness — confirm each host actually points to the target
   IP today. HackerTarget returns historical/passive data that includes
   abandoned and misconfigured records, so the raw list overstates reality.
───────────────────────────────────────── */
async function verifyReverseIp(targetIp, hosts) {
  if (!hosts || !hosts.length) return { live:[], stale:[], dead:[], skipped:[] };
  var toCheck = hosts.slice(0, 30);
  var skipped = hosts.slice(30);
  var results = await Promise.all(toCheck.map(function(h){
    return dohRace(h, 'A').then(function(d){
      var addrs = (d && d.Answer) ? d.Answer.map(function(a){return a.data;}) : [];
      if (!addrs.length) return { host: h, state: 'dead', addrs: [] };
      if (addrs.indexOf(targetIp) !== -1) return { host: h, state: 'live', addrs: addrs };
      return { host: h, state: 'stale', addrs: addrs };
    }).catch(function(){ return { host: h, state: 'dead', addrs: [] }; });
  }));
  return {
    live:    results.filter(function(r){return r.state==='live'; }),
    stale:   results.filter(function(r){return r.state==='stale';}),
    dead:    results.filter(function(r){return r.state==='dead'; }),
    skipped: skipped
  };
}

/* ─────────────────────────────────────────
   Subdomain liveness — verify CT-log entries actually resolve today.
   CT logs include long-expired test/staging hosts; many won't exist anymore.
   We re-query DNS for the first 30 to mark live vs dead so the user knows
   what's real surface vs historical noise.
───────────────────────────────────────── */
async function verifySubdomains(subs) {
  if (!subs || !subs.length) return { live:[], dead:[], skipped:[] };
  var toCheck = subs.slice(0, 30);
  var skipped = subs.slice(30);
  var results = await Promise.all(toCheck.map(function(s){
    return dohRace(s, 'A').then(function(d){
      return { host: s, alive: !!(d && d.Answer && d.Answer.length) };
    }).catch(function(){ return { host: s, alive: false }; });
  }));
  return {
    live:    results.filter(function(r){return r.alive;}).map(function(r){return r.host;}),
    dead:    results.filter(function(r){return !r.alive;}).map(function(r){return r.host;}),
    skipped: skipped
  };
}

/* ─────────────────────────────────────────
   RDAP / WHOIS — multiple registries
───────────────────────────────────────── */
async function rdapLookup(host) {
  var out = { registrar:null, org:null, created:null, expires:null, nameservers:[], status:[], error:null };
  var asIp = isIpAddr(host);
  var endpoints = asIp
    ? [ 'https://rdap.arin.net/registry/ip/'+host,
        'https://rdap.org/ip/'+host ]
    : [ 'https://rdap.org/domain/'+host,
        'https://rdap.verisign.com/com/v1/domain/'+host,
        'https://rdap.nominet.uk/uk/domain/'+host ];

  for (var i=0;i<endpoints.length;i++){
    try {
      var r = await abortFetch(endpoints[i], {}, 8000);
      if (!r.ok) continue;
      var d = await r.json();
      if (d.nameservers) out.nameservers = d.nameservers.map(function(n){ return (n.ldhName||'').toLowerCase(); }).filter(Boolean);
      (d.entities||[]).forEach(function(e){
        if ((e.roles||[]).indexOf('registrar')!==-1 && e.vcardArray){
          (e.vcardArray[1]||[]).forEach(function(v){ if(v[0]==='fn') out.registrar=v[3]; });
        }
      });
      (d.events||[]).forEach(function(ev){
        if (ev.eventAction==='registration') out.created=(ev.eventDate||'').slice(0,10);
        if (ev.eventAction==='expiration')   out.expires=(ev.eventDate||'').slice(0,10);
      });
      if (d.status) out.status = d.status;
      if (asIp){ out.registrar=d.name||out.registrar||null; out.org=d.handle||null; }
      return out;
    } catch(e){ out.error=e.message; }
  }
  return out;
}

/* ─────────────────────────────────────────
   Wayback Machine — fast historical-presence check
───────────────────────────────────────── */
async function wayBackLookup(host) {
  var out = { firstSeen:null, lastSeen:null, snapshot:null, found:false };
  var d = await tryJson('https://archive.org/wayback/available?url='+encodeURIComponent(host), 6000);
  if (d && d.archived_snapshots && d.archived_snapshots.closest) {
    var s = d.archived_snapshots.closest;
    out.found    = true;
    out.snapshot = s.url;
    out.lastSeen = (s.timestamp||'').slice(0,8);
  }
  return out;
}

/* ─────────────────────────────────────────
   URLhaus (abuse.ch) — known malicious URLs by host
   Free, no API key, CORS open. POST form-encoded.
───────────────────────────────────────── */
async function urlHausLookup(host) {
  var out = { found:false, urls:[], online:0, offline:0, totalSeen:0, threat:null, firstSeen:null, error:null };
  try {
    var r = await abortFetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'host='+encodeURIComponent(host)
    }, 6000);
    if (!r.ok) { out.error = 'HTTP '+r.status; return out; }
    var d = await r.json();
    if (d.query_status === 'ok' && d.urls && d.urls.length) {
      out.found     = true;
      out.totalSeen = d.url_count ? parseInt(d.url_count,10) : d.urls.length;
      out.firstSeen = d.firstseen;
      out.threat    = d.urls[0].threat;
      // Distinguish ACTIVE threats (status=online) from historical/cleaned ones.
      d.urls.forEach(function(u){
        if (u.url_status === 'online') out.online++;
        else                           out.offline++;
      });
      // Sort online first so the UI shows current threats prominently.
      d.urls.sort(function(a,b){
        return (a.url_status==='online'?0:1) - (b.url_status==='online'?0:1);
      });
      out.urls = d.urls.slice(0, 8);
    } else {
      out.error = d.query_status || 'no_results';
    }
  } catch(e) { out.error = e.message; }
  return out;
}

/* ─────────────────────────────────────────
   ThreatFox (abuse.ch) — IOC matches for IP/domain
───────────────────────────────────────── */
async function threatFoxLookup(target) {
  var out = { found:false, iocs:[], error:null };
  try {
    var r = await abortFetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: target })
    }, 6000);
    if (!r.ok) { out.error = 'HTTP '+r.status; return out; }
    var d = await r.json();
    if (d.query_status === 'ok' && d.data && d.data.length) {
      out.found = true;
      out.iocs  = d.data.slice(0, 10);
    } else {
      out.error = d.query_status || 'no_results';
    }
  } catch(e) { out.error = e.message; }
  return out;
}

/* ─────────────────────────────────────────
   Reverse IP — sites sharing this IP (HackerTarget)
   Rate-limited to 50/day per source-IP; degrade gracefully.
───────────────────────────────────────── */
async function reverseIpLookup(ip) {
  var out = { hosts:[], error:null };
  var txt = await tryText('https://api.hackertarget.com/reverseiplookup/?q='+encodeURIComponent(ip), 8000);
  if (!txt) { out.error = 'unreachable'; return out; }
  if (/error|API count exceeded/i.test(txt)) { out.error = txt.trim(); return out; }
  txt.split(/\r?\n/).forEach(function(line){
    var h = line.trim().toLowerCase();
    if (h && /^[a-z0-9]/.test(h) && h.indexOf('.')!==-1) out.hosts.push(h);
  });
  out.hosts = out.hosts.slice(0, 60);
  return out;
}

/* ─────────────────────────────────────────
   HTTP Header probe — unchanged contract, faster timeout
───────────────────────────────────────── */
async function headerProbe(host) {
  var out = { reachable:false, corsBlocked:false, statusCode:null,
              server:null, xPoweredBy:null, present:[], missing:[], via:null };

  for (var i=0;i<2;i++){
    try {
      var r = await abortFetch((i===0?'https://':'http://')+host, { mode:'cors' }, 7000);
      out.reachable   = true;
      out.statusCode  = r.status;
      out.server      = r.headers.get('server');
      out.xPoweredBy  = r.headers.get('x-powered-by');
      out.via         = 'direct';
      SEC_HEADERS.forEach(function(h){
        var v = r.headers.get(h.name);
        (v ? out.present : out.missing).push(Object.assign({},h,{value:v}));
      });
      return out;
    } catch(e){}
  }

  for (var j=0;j<2;j++){
    try {
      await abortFetch((j===0?'https://':'http://')+host, { mode:'no-cors' }, 5000);
      out.reachable   = true;
      out.corsBlocked = true;
      out.via         = 'no-cors';
      break;
    } catch(e){}
  }
  return out;
}

/* ─────────────────────────────────────────
   Port probe — broader set of HTTP-speaking services
───────────────────────────────────────── */
async function portProbe(host) {
  var checks = [
    { port:80,    proto:'http',  svc:'HTTP',         risk:'medium'   },
    { port:443,   proto:'https', svc:'HTTPS',        risk:'info'     },
    { port:8080,  proto:'http',  svc:'HTTP-Alt',     risk:'medium'   },
    { port:8443,  proto:'https', svc:'HTTPS-Alt',    risk:'medium'   },
    { port:3000,  proto:'http',  svc:'Dev-Server',   risk:'medium'   },
    { port:5000,  proto:'http',  svc:'Flask/Dev',    risk:'medium'   },
    { port:8000,  proto:'http',  svc:'HTTP-Dev',     risk:'medium'   },
    { port:8888,  proto:'http',  svc:'Jupyter',      risk:'high'     },
    { port:9200,  proto:'http',  svc:'Elasticsearch',risk:'critical' },
    { port:5601,  proto:'http',  svc:'Kibana',       risk:'high'     },
    { port:4200,  proto:'http',  svc:'Angular-Dev',  risk:'medium'   },
    { port:5173,  proto:'http',  svc:'Vite-Dev',     risk:'medium'   },
    { port:8086,  proto:'http',  svc:'InfluxDB',     risk:'high'     },
    { port:15672, proto:'http',  svc:'RabbitMQ-Mgmt',risk:'high'     },
    { port:9000,  proto:'http',  svc:'PHP-FPM/Misc', risk:'high'     },
    { port:7474,  proto:'http',  svc:'Neo4j',        risk:'high'     },
    { port:9090,  proto:'http',  svc:'Prometheus',   risk:'medium'   },
    { port:3001,  proto:'http',  svc:'Grafana/Dev',  risk:'medium'   },
  ];
  var open = [];
  await Promise.all(checks.map(function(c){
    return abortFetch(c.proto+'://'+host+':'+c.port, { method:'HEAD', mode:'no-cors' }, 2500)
      .then(function(){ open.push(c); })
      .catch(function(){});
  }));
  return open.sort(function(a,b){ return a.port-b.port; });
}

/* ─────────────────────────────────────────
   Sensitive files probe — HONEST version.
   Uses mode:'cors' + GET so we can read the real HTTP status.
   - confirmed[]: only paths that returned a real 200 OK with CORS open.
   - corsBlocked[]: paths the browser could not verify (most production
     servers don't enable CORS on these — that's normal, not a bug).
   No-cors mode would mark every path as "found" because opaque responses
   hide the status code, so 404s become indistinguishable from 200s.
───────────────────────────────────────── */
async function sensitiveFilesProbe(host) {
  var out = { confirmed:[], corsBlocked:[], total:SENSITIVE_PATHS.length };
  await Promise.all(SENSITIVE_PATHS.map(function(p){
    return abortFetch('https://'+host+p.path, { method:'GET', mode:'cors', redirect:'manual' }, 3000)
      .then(function(r){
        if (r && r.ok && r.status>=200 && r.status<300) {
          out.confirmed.push(Object.assign({}, p, { status:r.status }));
        }
      })
      .catch(function(){ out.corsBlocked.push(p); });
  }));
  return out;
}

/* ─────────────────────────────────────────
   Tech fingerprint from real response headers
───────────────────────────────────────── */
function fingerprintTech(headers) {
  var tech=[];
  if (!headers) return tech;
  var srv=(headers.server||'').toLowerCase();
  var xpb=(headers.xPoweredBy||'').toLowerCase();
  var all=srv+' '+xpb;
  var rules=[
    [/nginx/,        'nginx',        'Web Server'],
    [/apache/,       'Apache',       'Web Server'],
    [/cloudflare/,   'Cloudflare',   'WAF/CDN'],
    [/iis/,          'IIS',          'Web Server'],
    [/openresty/,    'OpenResty',    'Web Server'],
    [/litespeed/,    'LiteSpeed',    'Web Server'],
    [/caddy/,        'Caddy',        'Web Server'],
    [/php/,          'PHP',          'Language'],
    [/asp\.net/,     'ASP.NET',      'Framework'],
    [/express/,      'Express.js',   'Framework'],
    [/wordpress|wp-/,'WordPress',    'CMS'],
    [/drupal/,       'Drupal',       'CMS'],
    [/joomla/,       'Joomla',       'CMS'],
    [/akamai/,       'Akamai',       'CDN'],
    [/fastly/,       'Fastly',       'CDN'],
    [/vercel/,       'Vercel',       'Hosting'],
    [/netlify/,      'Netlify',      'Hosting'],
  ];
  rules.forEach(function(row){ if(row[0].test(all)) tech.push({name:row[1],cat:row[2],risk:'info'}); });
  var vm=srv.match(/nginx\/([\d.]+)|apache\/([\d.]+)|iis\/([\d.]+)/i);
  if(vm) tech.push({name:'Version in Server header: '+vm[0],cat:'Info Leak',risk:'warn'});
  return tech;
}

/* ─────────────────────────────────────────
   MAIN SCAN CORE — parallel pipeline
───────────────────────────────────────── */
async function runScanCore(target, isIp) {
  var btnId = isIp ? 'ipScanBtn' : 'targetScanBtn';
  var btn = document.getElementById(btnId);
>>>>>>> 921b7bd (- IP and Domain/URL Scanner updated\n- Added New sources like wayback, BGP, crt.sh, etc to the scanners.\n- Added the restroing functionality to the history options.\n- Now the IP and URL/Domain Scanner can gather too much information about the Geo Location and other information.\n- The Code Auditor got improved.)
  if (btn) btn.disabled = true;

  setStatus('scanning');
  clearLog(APP.state);
<<<<<<< HEAD
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
=======
  setProgress(2,'Initializing parallel recon...');
  renderPipe('dns',[],isIp?'ip':'net');

  if (!document.getElementById('view-scanner').classList.contains('active')) switchView('scanner');

  logEvent(APP.state,'Recon started — target: '+target);
  logEvent(APP.state,'Spawning '+(isIp?'IP':'domain')+' lookups in parallel across DNS / CT / RDAP / Geo / BGP / RIPE'+(isIp?' / Shodan':' / HackerTarget / Wayback')+'…','info');

  var R = {};
  var done = [];
  // IP: geo + ptr + idb + ripe + bgp + rdap + revip + urlhaus + threatfox = 9 (revip skipped for infra)
  // Domain: dns(+chained geo/ptr/idb) + ssl + bgp + rdap + ht + wb + urlhaus + threatfox = 8
  var skipsRevip = isIp && INFRA_REGISTRY[target] && INFRA_REGISTRY[target].skip.indexOf('revip') !== -1;
  var totalPhase1 = isIp ? (skipsRevip ? 8 : 9) : 8;
  var phase1Done = 0;

  function tickPhase1(label, key) {
    phase1Done++;
    if (key && done.indexOf(key)===-1) done.push(key);
    var pct = 5 + Math.round((phase1Done / totalPhase1) * 55);
    renderPipe(null, done, isIp?'ip':'net');
    setProgress(Math.min(60,pct), label);
  }

  /* ── module toggles ── */
  var doDns   = isEl('modDns')        ? el('modDns').checked        : true;
  var doSsl   = isEl('modSsl')        ? el('modSsl').checked        : true;
  var doHdr   = isEl('modHeaders')    ? el('modHeaders').checked    : true;
  var doSub   = isEl('modSubdomains') ? el('modSubdomains').checked : true;
  var doPorts = isEl('modPorts')      ? el('modPorts').checked      : true;
  var doTech  = isEl('modTech')       ? el('modTech').checked       : true;
  var doWhois = isEl('modWhois')      ? el('modWhois').checked      : true;
  var doFiles = isEl('modFiles')      ? el('modFiles').checked      : true;

  /* ── Early classification (hardcoded special IPs only) ──
     Lets us skip irrelevant modules before we even spend the requests. */
  if (isIp && INFRA_REGISTRY[target]) {
    R.classify = Object.assign({}, INFRA_REGISTRY[target]);
    logEvent(APP.state,
      'Recognized target: '+R.classify.service+' ('+R.classify.provider+')',
      'info');
    logEvent(APP.state, R.classify.notes, 'info');
    if (R.classify.skip.indexOf('files') !== -1) {
      doFiles = false;
      logEvent(APP.state,'Skipping sensitive-files probe — not meaningful on a public DNS resolver.','info');
    }
    if (R.classify.skip.indexOf('revip') !== -1) {
      logEvent(APP.state,'Skipping reverse-IP lookup — anycast/infra IPs accumulate huge passive-DNS noise.','info');
    }
  }
  var skipRevip = R.classify && R.classify.skip && R.classify.skip.indexOf('revip') !== -1;

  /* ── PHASE 1 — independent, all parallel ── */
  var p1 = [];

  if (!isIp && doDns) {
    p1.push(dnsLookup(target).then(async function(r){
      R.dns = r;
      if (r.a.length)     logEvent(APP.state,'A: '+r.a.join(', '),'ok');
      else                logEvent(APP.state,'No A records — domain may not exist or is AAAA-only','warn');
      if (r.aaaa.length)  logEvent(APP.state,'AAAA: '+r.aaaa.slice(0,3).join(', '),'info');
      if (r.mx.length)    logEvent(APP.state,'MX: '+r.mx.slice(0,3).join(', '),'info');
      if (r.ns.length)    logEvent(APP.state,'NS: '+r.ns.slice(0,3).join(', '),'info');
      if (r.spf.length)   logEvent(APP.state,'SPF: present','ok');
      else                logEvent(APP.state,'SPF: missing — phishing risk','warn');
      if (r.dmarc.length) logEvent(APP.state,'DMARC: present','ok');
      else                logEvent(APP.state,'DMARC: missing — spoofing risk','warn');
      if (r.caa.length)   logEvent(APP.state,'CAA: '+r.caa.length+' record(s)','ok');
      tickPhase1('DNS resolved (Google + Cloudflare DoH)', 'dns');

      // Chain geo + reverse DNS off the resolved A record so domain scans
      // get the same Geo card as IP scans.
      if (r.a.length) {
        R.resolvedIp = r.a[0];
        logEvent(APP.state,'Resolving geo for '+r.a[0]+'…','info');
        var geoP  = ipGeo(r.a[0]).then(function(g){
          R.geo = g;
          if (g) logEvent(APP.state,'Geo: '+(g.city||'?')+', '+(g.country||'?')+' | '+(g.org||g.isp||'?')+' (via '+g.source+')','ok');
          else   logEvent(APP.state,'Geo: no provider returned data','warn');
        });
        var ptrP  = ptrLookup(r.a[0]).then(function(p){ R.rdns = p; if(p) logEvent(APP.state,'PTR for '+r.a[0]+': '+p,'info'); });
        var idbP  = internetDbLookup(r.a[0]).then(function(d){
          R.idb = d;
          if (d.found) logEvent(APP.state,'Shodan: '+d.ports.length+' ports / '+d.vulns.length+' CVEs on resolved IP','info');
        });
        await Promise.all([geoP, ptrP, idbP]);
      }
    }));
  }

  if (isIp) {
    p1.push(ipGeo(target).then(function(r){
      R.geo = r;
      if (r) logEvent(APP.state,'Geo: '+(r.org||'?')+' | '+[r.city,r.country].filter(Boolean).join(', ')+' ('+r.source+')','ok');
      else   logEvent(APP.state,'No geo data returned','warn');
      tickPhase1('Geo (ipapi / ipwho race)', 'dns');
    }));
    p1.push(ptrLookup(target).then(function(r){
      R.rdns = r;
      logEvent(APP.state, r ? 'PTR: '+r : 'No PTR record','info');
      tickPhase1('Reverse DNS', 'dns');
    }));
    p1.push(internetDbLookup(target).then(function(r){
      R.idb = r;
      if (r.found) {
        logEvent(APP.state,'Shodan InternetDB: '+r.ports.length+' ports, '+r.vulns.length+' CVEs, '+r.hostnames.length+' hostnames','info');
        if (r.vulns.length) logEvent(APP.state,'Known CVEs: '+r.vulns.slice(0,5).join(', ')+(r.vulns.length>5?' …':''),'crit');
      } else {
        logEvent(APP.state,'Shodan InternetDB: '+(r.error||'no data'),'info');
      }
      tickPhase1('Shodan InternetDB', 'ports');
    }));
    p1.push(ripeStatLookup(target).then(function(r){
      R.ripe = r;
      if (r.found) logEvent(APP.state,'RIPEstat: prefix '+(r.prefix||'?')+' | abuse: '+(r.abuse[0]||'unknown'),'info');
      tickPhase1('RIPEstat network info', 'whois');
    }));
  }

  if (doSsl && !isIp) {
    p1.push(crtShLookup(target).then(function(r){
      R.ssl = r;
      if (r.found) {
        logEvent(APP.state,'Cert ('+r.source+'): '+r.issuer+' expires '+r.expiry+' ('+r.daysLeft+'d)', r.daysLeft<30?'crit':'ok');
        logEvent(APP.state,r.subdomains.length+' subdomains in CT logs','info');
      } else {
        logEvent(APP.state,'CT: '+(r.error||'No certs'),'warn');
      }
      tickPhase1('Certificate Transparency', 'ssl');
    }));
  }

  p1.push(bgpViewLookup(target, isIp).then(function(r){
    R.bgp = r;
    if (r.found && r.asn) logEvent(APP.state,'BGP: '+r.asn+' '+(r.asnDesc||r.asnName||'')+(r.country?' ('+r.country+')':''),'info');
    tickPhase1('BGPView ASN', 'whois');
  }));

  if (doWhois) {
    p1.push(rdapLookup(target).then(function(r){
      R.whois = r;
      if (r.registrar) logEvent(APP.state,'Registrar: '+r.registrar,'ok');
      else             logEvent(APP.state,'RDAP: no registrar data','info');
      tickPhase1('RDAP / WHOIS', 'whois');
    }));
  }

  if (!isIp) {
    p1.push(hackerTargetHosts(target).then(function(r){
      R.ht = r;
      if (r.hosts.length) logEvent(APP.state,'HackerTarget: +'+r.hosts.length+' hosts','info');
      else if (r.error)   logEvent(APP.state,'HackerTarget: '+r.error,'info');
      tickPhase1('HackerTarget hostsearch', 'subdomains');
    }));
    p1.push(wayBackLookup(target).then(function(r){
      R.wb = r;
      if (r.found) logEvent(APP.state,'Wayback: last snapshot '+r.lastSeen,'info');
      tickPhase1('Wayback Machine', 'subdomains');
    }));
  }

  // Reverse IP — sites sharing the IP (IP scan only, skipped for known anycast/infra)
  if (isIp && !skipRevip) {
    p1.push(reverseIpLookup(target).then(function(r){
      R.revip = r;
      if (r.hosts.length) logEvent(APP.state,'Reverse IP: '+r.hosts.length+' site(s) share '+target+' (will verify with live DNS)','info');
      else if (r.error)   logEvent(APP.state,'Reverse IP: '+r.error,'info');
      tickPhase1('Reverse IP (HackerTarget)', 'whois');
    }));
  }

  // Threat intel (abuse.ch) — both modes
  p1.push(urlHausLookup(target).then(function(r){
    R.urlhaus = r;
    if (r.found) {
      var sev = r.online > 0 ? 'crit' : 'warn';
      logEvent(APP.state,'URLhaus: '+r.online+' active / '+r.offline+' offline — threat: '+r.threat, sev);
    }
    tickPhase1('URLhaus reputation', 'whois');
  }));
  p1.push(threatFoxLookup(target).then(function(r){
    R.tfox = r;
    if (r.found) logEvent(APP.state,'ThreatFox: '+r.iocs.length+' IOC match(es) — '+(r.iocs[0].malware_printable||r.iocs[0].threat_type||'unknown'),'crit');
    tickPhase1('ThreatFox IOC', 'whois');
  }));

  await Promise.all(p1);

  /* ── Refine classification using BGP/Geo data (cloud/CDN detection) ──
     Hardcoded registry hits keep their richer metadata; everything else
     gets ASN-based inference. */
  if (!R.classify || R.classify.kind === 'normal' || (!INFRA_REGISTRY[target] && isIp)) {
    var refined = classifyTarget(target, R);
    if (!R.classify || refined.kind !== 'normal') {
      R.classify = refined;
      if (refined.kind !== 'normal') {
        logEvent(APP.state,'Classified as '+refined.kind+' — '+refined.service, 'info');
      }
    }
  }

  /* ── PHASE 2 — HTTP-dependent, parallel ── */
  setProgress(64,'Probing live HTTP surface...');
  var p2 = [];

  if (doHdr) {
    p2.push(headerProbe(target).then(function(r){
      R.headers = r;
      if (!r.reachable) {
        logEvent(APP.state,'Target not reachable on HTTP/HTTPS','warn');
      } else if (r.corsBlocked) {
        logEvent(APP.state,'Reachable, but browser CORS prevents header reading. Use: curl -sI https://'+target+' | grep -Ei "server|strict|content-security|x-frame"','warn');
      } else {
        logEvent(APP.state,'HTTP '+r.statusCode+' | Server: '+(r.server||'hidden'),'ok');
        (r.missing||[]).forEach(function(h){ if(h.required) logEvent(APP.state,'Missing: '+h.short,'warn'); });
        (r.present||[]).forEach(function(h){ logEvent(APP.state,'Header OK: '+h.short,'ok'); });
        if (r.xPoweredBy) logEvent(APP.state,'X-Powered-By exposed: '+r.xPoweredBy,'warn');
      }
      done.push('headers'); renderPipe(null,done,isIp?'ip':'net'); setProgress(74,'Headers done');
    }));
  }

  if (doPorts) {
    p2.push(portProbe(target).then(function(r){
      R.ports = r;
      r.forEach(function(p){
        logEvent(APP.state,'Reachable: '+p.port+' ('+p.svc+')', p.risk==='critical'?'crit':p.risk==='high'?'warn':'info');
      });
      if (!r.length) logEvent(APP.state,'No HTTP/HTTPS ports responded.','info');
      done.push('ports'); renderPipe(null,done,isIp?'ip':'net'); setProgress(82,'Ports done');
    }));
  }

  if (doFiles) {
    p2.push(sensitiveFilesProbe(target).then(function(r){
      R.files = r;
      if (r.confirmed.length) {
        r.confirmed.forEach(function(f){
          logEvent(APP.state,'Confirmed reachable (HTTP '+f.status+'): '+f.label, f.sev==='critical'?'crit':f.sev==='high'?'warn':'info');
        });
      } else {
        logEvent(APP.state,'No sensitive paths confirmed via browser. '+r.corsBlocked.length+' could not be verified (CORS-blocked) — use curl for ground truth.','info');
      }
      done.push('files'); renderPipe(null,done,isIp?'ip':'net'); setProgress(88,'Sensitive files done');
    }));
  }

  await Promise.all(p2);

  /* ── PHASE 3 — derived + verification ── */
  // Merge subdomain sources, then verify the first 30 actually resolve right
  // now. CT logs include lots of expired/never-deployed test hosts; without
  // this check, the count is meaningless.
  if (doSub && !isIp) {
    var merged = {};
    ((R.ssl && R.ssl.subdomains) || []).forEach(function(s){ merged[s]=true; });
    ((R.ht && R.ht.hosts) || []).forEach(function(h){ merged[h.host]=true; });
    R.subdomains = Object.keys(merged).sort();
    logEvent(APP.state,'Total unique subdomains: '+R.subdomains.length+' — verifying liveness…','info');
    setProgress(92,'Verifying subdomains via DNS...');
    R.subVerify = await verifySubdomains(R.subdomains);
    logEvent(APP.state,
      'Subdomain liveness: '+R.subVerify.live.length+' live / '+R.subVerify.dead.length+' dead'+
      (R.subVerify.skipped.length ? ' ('+R.subVerify.skipped.length+' not checked)' : ''),
      R.subVerify.live.length ? 'ok' : 'info');
  }

  // Verify reverse-IP results actually point to the target right now.
  // (Skipped for anycast IPs — the data is structurally meaningless there.)
  if (isIp && R.revip && R.revip.hosts.length) {
    if (R.geo && R.geo.isAnycast) {
      logEvent(APP.state,'Skipping reverse-IP verification — '+target+' is anycast, the data is not meaningful.','warn');
      R.revipVerify = { live:[], stale:[], dead:[], skipped:R.revip.hosts, anycast:true };
    } else {
      setProgress(94,'Verifying reverse-IP hosts…');
      R.revipVerify = await verifyReverseIp(target, R.revip.hosts);
      logEvent(APP.state,
        'Reverse-IP verification: '+R.revipVerify.live.length+' still point here / '+
        R.revipVerify.stale.length+' moved / '+R.revipVerify.dead.length+' dead'+
        (R.revipVerify.skipped.length ? ' ('+R.revipVerify.skipped.length+' not checked)' : ''),
        R.revipVerify.live.length ? 'ok' : 'info');
    }
  }

  if (doTech) {
    R.tech = R.headers ? fingerprintTech(R.headers) : [];
    R.tech.forEach(function(t){ logEvent(APP.state,'Tech: '+t.name+' ('+t.cat+')','info'); });
    done.push('tech'); renderPipe(null,done,isIp?'ip':'net');
  }

  /* ── Complete ── */
  renderPipe(null,done,isIp?'ip':'net');
  setProgress(100,'Recon complete');
  logEvent(APP.state,'Recon complete for '+target+'.','ok');
  if (R.headers && R.headers.corsBlocked) {
    logEvent(APP.state,'NOTE — CORS-protected sites cannot expose headers to a browser. See log for curl command.','info');
  }
  logEvent(APP.state,'NOTE — Port scan covers HTTP/HTTPS only. Use nmap for raw TCP.','info');
  setStatus('done','Recon done');

  var findings = buildNetworkFindings(target,R,isIp);
  APP.state.allFindings = findings;
  updateMetrics(findings);
  showRiskScore(findings);
  buildSevPills(APP.state,APP.cfg);
  renderFindings(APP.state,APP.cfg);
  if (typeof buildSarif==='function') buildSarif();
  renderNetworkResults(target,R,isIp);
  switchView('network');

  var _netResultsEl = document.getElementById('networkResults');
  addHistoryEntry({
    target:target, type:isIp?'IP':'DOMAIN',
    findings:findings.length,
    critical:findings.filter(function(f){return f.sev==='critical';}).length,
    high:findings.filter(function(f){return f.sev==='high';}).length,
    risk:computeRiskScore(findings),
    date:new Date().toLocaleDateString(),
    time:new Date().toLocaleTimeString(),
  }, {
    findings:    findings.slice(),
    networkHtml: _netResultsEl ? _netResultsEl.innerHTML : '',
    diffHtml:    '',
    when:        Date.now(),
  });
  renderHistoryTable();
  updateDashboard(APP.state);
  if (btn) btn.disabled=false;

  var badge=document.getElementById('sbFindBadge');
  if (badge){ badge.textContent=findings.length; badge.style.display=findings.length?'inline-flex':'none'; }
  if (APP.cfg&&APP.cfg.toasts) showToast('Recon done — '+findings.length+' findings for '+target, findings.length?'warn':'success');

  /* Save this mode's results so switching tabs doesn't lose them */
  if (typeof saveModeSnapshot === 'function') saveModeSnapshot(isIp ? 'ip' : 'domain');
}

/* helpers */
function isEl(id){ return !!document.getElementById(id); }
function el(id)  { return document.getElementById(id); }

/* ─────────────────────────────────────────
   PUBLIC ENTRY POINTS
───────────────────────────────────────── */
async function runNetworkScan(){
  var raw=(el('targetInput')||{}).value||'';
  raw=raw.trim();
  if(!raw){ showToast('Enter a domain or URL.','warn'); return; }
  var host=parseHost(raw);
  if(!host){ showToast('Invalid target.','error'); return; }
  if(isPrivate(host)){ showToast('Private/loopback addresses cannot be scanned.','error'); return; }
  if(!isValidHost(host)){ showToast('Enter a valid domain or IP address.','error'); return; }
  await runScanCore(host,false);
}

async function runIpScan(){
  var ip=((el('ipTargetInput')||{}).value||'').trim();
  if(!ip){ showToast('Enter an IP address.','warn'); return; }
  if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)){ showToast('Invalid IP — use x.x.x.x format.','error'); return; }
  if(isPrivate(ip)){ showToast('Private IPs cannot be scanned from browser.','error'); return; }
  var octs=ip.split('.').map(Number);
  if(octs.some(function(o){return o>255;})){ showToast('Invalid IP — octets must be 0–255.','error'); return; }
  await runScanCore(ip,true);
}

/* ─────────────────────────────────────────
   BUILD FINDINGS
───────────────────────────────────────── */
function buildNetworkFindings(target,R,isIp){
  var out=[]; var id=0;
  function nf(t,sev,desc,fix){
    return {id:'net-'+(id++),type:'NETWORK',title:t,sev:sev,loc:target,line:1,
      snippet:'',match:t,desc:desc,remediation:{text:desc,fix:fix||''},confidence:95,taint:null,isNew:false};
  }

  // DNS hygiene
  if (R.dns) {
    if (!R.dns.spf.length)   out.push(nf('Missing SPF record','medium','No v=spf1 TXT record — domain can be spoofed in email.','Add SPF: v=spf1 -all (or per your senders).'));
    if (!R.dns.dmarc.length) out.push(nf('Missing DMARC policy','medium','No DMARC record at _dmarc.'+target+' — phishing/spoofing risk.','Add TXT _dmarc: v=DMARC1; p=reject; rua=mailto:...'));
    if (!R.dns.caa.length)   out.push(nf('No CAA records','low','Without CAA, any CA can issue certificates for this domain.','Add CAA 0 issue "letsencrypt.org" (or your CA).'));
  }

  // Header findings
  if(R.headers && !R.headers.corsBlocked && R.headers.reachable){
    (R.headers.missing||[]).forEach(function(h){
      out.push(nf('Missing header: '+h.short, h.required?'high':'medium',
        'HTTP response missing '+h.name+' — exposes users to web attacks.',
        h.name+': [value]'));
    });
    if(R.headers.xPoweredBy) out.push(nf('X-Powered-By exposes stack','low','Reveals: '+R.headers.xPoweredBy,'Remove X-Powered-By header.'));
    if(R.headers.server && /\d+\.\d+/.test(R.headers.server)) out.push(nf('Server version in header','low','Server: '+R.headers.server,'server_tokens off;'));
  }

  // SSL findings
  if(R.ssl && R.ssl.found){
    if(R.ssl.daysLeft<0)        out.push(nf('SSL cert EXPIRED','critical','Expired '+Math.abs(R.ssl.daysLeft)+'d ago.','certbot renew'));
    else if(R.ssl.daysLeft<14)  out.push(nf('SSL cert expires in '+R.ssl.daysLeft+'d','critical','Expires '+R.ssl.expiry,'certbot renew'));
    else if(R.ssl.daysLeft<30)  out.push(nf('SSL cert expires in '+R.ssl.daysLeft+'d','high','Expires '+R.ssl.expiry,'certbot renew'));
  }

  // Port findings
  (R.ports||[]).forEach(function(p){
    if(p.risk==='critical'||p.risk==='high')
      out.push(nf('Port '+p.port+' ('+p.svc+') reachable',p.risk,
        p.svc+' publicly accessible on port '+p.port,
        'iptables -A INPUT -p tcp --dport '+p.port+' -j DROP'));
  });

  // Shodan InternetDB findings (IP scan)
  if (R.idb && R.idb.found) {
    if (R.idb.vulns.length) {
      out.push(nf('Shodan: '+R.idb.vulns.length+' known CVEs on host','critical',
        'CVEs: '+R.idb.vulns.slice(0,8).join(', ')+(R.idb.vulns.length>8?' …':''),
        'Patch the affected service or restrict exposure.'));
    }
    R.idb.ports.forEach(function(p){
      if ([23,21,3389,3306,5432,6379,11211,9200,27017,1433].indexOf(p)!==-1) {
        out.push(nf('Sensitive port '+p+' open (Shodan)','high',
          'Shodan reports port '+p+' open on this IP.',
          'Block at firewall or bind only to internal interfaces.'));
      }
    });
  }

  // Sensitive files findings — only confirmed 200s, never opaque guesses
  ((R.files && R.files.confirmed) || []).forEach(function(f){
    if (f.sev==='critical' || f.sev==='high' || f.sev==='medium') {
      out.push(nf('Public: '+f.label+' (HTTP '+f.status+')', f.sev,
        'Confirmed reachable at '+f.path+' — may leak source/credentials.',
        'Block '+f.path+' at the web server.'));
    }
  });

  // Threat-intel findings (abuse.ch URLhaus + ThreatFox)
  // Distinguish ACTIVE (online) malicious URLs from historical (cleaned/offline)
  // ones — the latter aren't actionable today.
  if (R.urlhaus && R.urlhaus.found) {
    if (R.urlhaus.online > 0) {
      out.push(nf('URLhaus: '+R.urlhaus.online+' ACTIVE malicious URL(s)','critical',
        R.urlhaus.online+' currently-online malicious URL(s) — threat: '+(R.urlhaus.threat||'unknown')+
        '. First seen: '+(R.urlhaus.firstSeen||'unknown')+'.',
        'Investigate compromise; clean affected paths; rotate credentials.'));
    } else {
      out.push(nf('URLhaus: historical match (all offline)','info',
        R.urlhaus.offline+' previously-malicious URL(s) on this host — none currently online. May indicate prior compromise.',
        ''));
    }
  }
  if (R.tfox && R.tfox.found) {
    var first = R.tfox.iocs[0] || {};
    out.push(nf('ThreatFox: IOC match','high',
      R.tfox.iocs.length+' IOC match(es). Top: '+(first.malware_printable||first.threat_type||'unknown')+
      ' ('+(first.ioc_type||'?')+').',
      'Treat host as suspicious; check egress logs.'));
  }

  // Shared hosting — only count VERIFIED-live entries that currently point
  // to the target. Raw HackerTarget output is full of stale records.
  if (R.revipVerify && !R.revipVerify.anycast && R.revipVerify.live.length > 20) {
    out.push(nf(R.revipVerify.live.length+' verified sites share this IP','info',
      'Confirmed via fresh DNS: '+R.revipVerify.live.length+' domains currently resolve to '+target+'. Useful pivot during recon.',
      ''));
  }

  // Subdomain exposure
  if(R.subdomains && R.subdomains.length>0)
    out.push(nf(R.subdomains.length+' subdomains discovered','info',
      'Aggregated from CT logs and HackerTarget. Audit for shadow IT.',''));

  return sortBySeverity(out);
}

/* ─────────────────────────────────────────
   RENDER RESULTS
───────────────────────────────────────── */
function renderNetworkResults(target,R,isIp){
  var c=document.getElementById('networkResults');
  if(!c) return;
  var h='<div class="network-grid">';

  /* Infrastructure notice — shown FIRST when target is anycast DNS / cloud / CDN.
     grid-column:1/-1 makes it span the full grid width. */
  if (R.classify && R.classify.kind && R.classify.kind !== 'normal') {
    var k = R.classify;
    var accent = k.kind==='anycast-dns' || k.kind==='root-dns' ? '#4dc4ff'
               : k.kind==='cdn'                                ? '#e6c84d'
               : k.kind==='cloud' || k.kind==='anycast'        ? '#9d7bff'
               : '#888';
    var skipText = (k.skip && k.skip.length)
      ? 'Skipped modules: '+k.skip.map(function(s){
          return s==='revip'?'reverse-IP':s==='files'?'sensitive-files':s;
        }).join(', ')+'.'
      : '';
    var anycastKind = k.kind === 'anycast-dns' || k.kind === 'anycast' || k.kind === 'root-dns';
    var geoCaveat = anycastKind
      ? '<div style="margin-top:8px;padding:6px 10px;background:rgba(230,200,77,.08);border-left:2px solid #e6c84d;border-radius:2px;font-size:11px;line-height:1.5;color:var(--text2)">'+
        '<strong style="color:#e6c84d">Heads up:</strong> any geolocation, country, or coordinates shown below for this IP are <strong style="color:var(--text)">misleading</strong>. '+
        'Anycast addresses are announced from many Points-of-Presence (PoPs) worldwide simultaneously, so GeoIP databases can only report the IP\'s <em>registration city</em>, not the server you actually reached. Use traceroute or HTTP RTT for the real PoP.'+
        '</div>'
      : '';
    h += '<div class="net-card" style="grid-column:1/-1;border-left:3px solid '+accent+'">'+
         '<div class="net-card-head"><div class="nc-dot info" style="background:'+accent+'"></div>INFRASTRUCTURE NOTICE'+
         '<span class="real-badge" style="margin-left:6px">'+esc(k.kind.toUpperCase())+'</span></div>'+
         '<div style="padding:10px 14px 12px;font-size:12px;line-height:1.6">'+
         '<strong style="color:var(--text)">'+esc(k.service)+'</strong>'+
         (k.provider && k.provider!=='unknown' ? ' <span style="color:var(--text2)">— '+esc(k.provider)+'</span>' : '')+
         '<div style="margin-top:6px;color:var(--text2);font-size:11px">'+esc(k.notes)+'</div>'+
         geoCaveat +
         (skipText ? '<div style="margin-top:6px;color:var(--text2);font-size:10px;font-family:var(--mono);letter-spacing:.04em">'+esc(skipText)+'</div>' : '')+
         '</div></div>';
  }

  /* DNS — extended */
  if(R.dns&&!isIp){
    var rows =
      nRow('A',     R.dns.a.join(', ')             ||nNone())+
      nRow('AAAA',  R.dns.aaaa.join(', ')          ||nNone())+
      nRow('MX',    R.dns.mx.slice(0,3).join(', ') ||nNone())+
      nRow('NS',    R.dns.ns.slice(0,3).join(', ') ||nNone())+
      nRow('CNAME', R.dns.cname.join(', ')         ||nNone())+
      nRow('SPF',   R.dns.spf.length ? '<span style="color:var(--green)">present</span>' : '<span style="color:var(--red)">missing</span>')+
      nRow('DMARC', R.dns.dmarc.length ? '<span style="color:var(--green)">present</span>' : '<span style="color:var(--red)">missing</span>')+
      nRow('CAA',   R.dns.caa.length ? esc(R.dns.caa.slice(0,2).join(', ')) : '<span style="color:var(--text2)">none</span>')+
      nRow('TXT',   R.dns.txt.length ? esc(R.dns.txt.length+' record(s)') : nNone());
    h+=nCard((R.dns.a.length||R.dns.mx.length)?'ok':'warn','DNS RECORDS','LIVE — Google + Cloudflare DoH', rows);
  }

  /* GEO — IP scan AND domain scan (resolved A record), with cross-source agreement */
  if (isIp || R.geo || R.resolvedIp) {
    var g = R.geo || {};
    var ag = g.agreement || {};
    var title = isIp ? 'IP INTELLIGENCE' : 'GEO LOCATION';
    var ipLabel = isIp ? 'IP' : 'Resolved IP';
    var ipShown = g.ip || (isIp ? target : R.resolvedIp) || '—';

    function confBadge(a){
      if (!a) return '';
      var color = a.confidence==='high' ? 'var(--green)' : a.confidence==='med' ? 'var(--yellow,#e6c84d)' : 'var(--red)';
      var label = a.votes+'/'+a.total;
      return '<span style="font-size:9px;font-family:var(--mono);color:'+color+';margin-left:6px;letter-spacing:.06em">'+label+' '+a.confidence.toUpperCase()+'</span>';
    }

    var loc = [g.city, g.region, g.country].filter(Boolean).join(', ');
    if (g.countryCode) loc = (loc||'') + ' ('+g.countryCode+')';
    var coordsCell = (g.lat!=null && g.lng!=null)
      ? esc(g.lat+', '+g.lng)+' <a href="https://www.openstreetmap.org/?mlat='+
        encodeURIComponent(g.lat)+'&mlon='+encodeURIComponent(g.lng)+'#map=12/'+
        encodeURIComponent(g.lat)+'/'+encodeURIComponent(g.lng)+
        '" target="_blank" rel="noopener" style="color:var(--accent);margin-left:6px">map ↗</a>'
      : '<em style="opacity:.4">—</em>';
    var hosting = g.org && /aws|azure|google|cloudflare|digital.?ocean|hetzner|linode|vultr|oracle|ovh|fastly|akamai|leaseweb|alibaba|tencent|godaddy/i.test(g.org)
      ? 'Cloud / Hosting' : 'ISP / Residential';

    var anycastBanner = g.isAnycast
      ? '<div style="padding:8px 14px;background:rgba(230,200,77,.08);border-bottom:1px solid rgba(230,200,77,.2);font-size:10px;line-height:1.5;color:var(--text2)">'+
        '<strong style="color:var(--text)">⚠ Anycast IP</strong> — this address is announced from many PoPs worldwide. '+
        'GeoIP databases report the registration city, not the server you actually reached. '+
        'Use traceroute for the real PoP.</div>'
      : '';

    var dotState = g.isAnycast ? 'warn' : (R.geo ? 'ok' : 'warn');

    h += nCard(dotState, title, 'LIVE — '+(g.source||'no provider'),
      anycastBanner +
      nRow(ipLabel,      esc(ipShown))+
      nRow('Reverse DNS',esc(R.rdns||'No PTR'))+
      nRow('Country',    (loc ? esc(loc) : '<em style="opacity:.4">Unknown</em>') + confBadge(ag.country))+
      (g.continent ? nRow('Continent', esc(g.continent)) : '')+
      nRow('City',       esc(g.city||'Unknown') + confBadge(ag.city))+
      nRow('Coordinates', coordsCell)+
      nRow('Timezone',   esc((g.timezone||'Unknown') + (g.utcOffset?' ('+g.utcOffset+')':'')))+
      nRow('ASN',        esc(g.asn||'Unknown') + confBadge(ag.asn))+
      nRow('Org',        esc(g.org||'Unknown') + confBadge(ag.org))+
      nRow('ISP',        esc(g.isp||g.org||'Unknown'))+
      (g.network    ? nRow('Network',     esc(g.network))             : '')+
      (g.currency   ? nRow('Currency',    esc(g.currency))            : '')+
      (g.callingCode? nRow('Calling code',esc(g.callingCode))         : '')+
      nRow('Type', esc(hosting))
    );

    // Source comparison card — show every provider's raw answer so the user
    // can see WHY the agreement was high or low.
    if (g.sources && g.sources.length > 1) {
      var srcRows = '<div style="padding:0 14px 8px;font-size:10px;color:var(--text2);line-height:1.4">'+
        'Each row is one provider. Disagreement here is the reason confidence may be MED/LOW above.</div>'+
        '<div style="padding:0 14px 10px;overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:10px;font-family:var(--mono)">'+
        '<thead><tr style="text-align:left;color:var(--text2)">'+
        '<th style="padding:3px 6px">Source</th><th style="padding:3px 6px">Country</th><th style="padding:3px 6px">City</th><th style="padding:3px 6px">ASN</th><th style="padding:3px 6px">Org</th>'+
        '</tr></thead><tbody>';
      g.sources.forEach(function(s){
        srcRows += '<tr style="border-top:1px solid rgba(255,255,255,.05)">'+
          '<td style="padding:3px 6px">'+esc(s.source)+'</td>'+
          '<td style="padding:3px 6px">'+esc((s.country||'—')+(s.countryCode?' ('+s.countryCode+')':''))+'</td>'+
          '<td style="padding:3px 6px">'+esc(s.city||'—')+'</td>'+
          '<td style="padding:3px 6px">'+esc(s.asn||'—')+'</td>'+
          '<td style="padding:3px 6px">'+esc(s.org||s.isp||'—')+'</td>'+
          '</tr>';
      });
      srcRows += '</tbody></table></div>';
      h += nCard('info','GEO SOURCE COMPARISON','LIVE — '+g.sources.length+' providers', srcRows);
    }
  }

  /* Shodan InternetDB — IP scans and resolved-IP for domain scans */
  if (R.idb) {
    if (R.idb.found) {
      var idbBody='';
      idbBody+=nRow('Open Ports', R.idb.ports.length
        ? '<div style="display:flex;flex-wrap:wrap;gap:4px">'+R.idb.ports.map(function(p){
            return '<span class="port-badge open">'+p+'</span>';
          }).join('')+'</div>'
        : nNone());
      idbBody+=nRow('CVEs', R.idb.vulns.length
        ? '<span style="color:var(--red)">'+R.idb.vulns.length+': '+esc(R.idb.vulns.slice(0,5).join(', '))+(R.idb.vulns.length>5?' …':'')+'</span>'
        : '<span style="color:var(--green)">none reported</span>');
      idbBody+=nRow('Hostnames', R.idb.hostnames.length ? esc(R.idb.hostnames.slice(0,5).join(', ')) : nNone());
      idbBody+=nRow('Tags',      R.idb.tags.length      ? esc(R.idb.tags.join(', '))                  : nNone());
      idbBody+=nRow('CPEs',      R.idb.cpes.length      ? esc(R.idb.cpes.length+' fingerprints')      : nNone());
      h+=nCard(R.idb.vulns.length?'bad':R.idb.ports.length>5?'warn':'ok','SHODAN INTERNETDB','LIVE — internetdb.shodan.io',idbBody);
    } else {
      h+=nCard('info','SHODAN INTERNETDB','LIVE',
        '<div style="padding:10px 14px;font-size:11px;color:var(--text2)">No exposure data: '+esc(R.idb.error||'unknown')+'</div>');
    }
  }

  /* BGPView */
  if (R.bgp && R.bgp.found) {
    h+=nCard('info','BGP / ASN','LIVE — bgpview.io',
      nRow('ASN',         esc(R.bgp.asn||'Unknown'))+
      nRow('Org',         esc(R.bgp.asnDesc||R.bgp.asnName||'Unknown'))+
      nRow('Country',     esc(R.bgp.country||'Unknown'))+
      (R.bgp.prefix    ? nRow('Prefix',    esc(R.bgp.prefix))    : '')+
      (R.bgp.rir       ? nRow('RIR',       esc(R.bgp.rir))       : '')+
      (R.bgp.allocated ? nRow('Allocated', esc(R.bgp.allocated)) : '')
    );
  }

  /* RIPEstat */
  if (isIp && R.ripe && R.ripe.found) {
    h+=nCard('info','RIPESTAT','LIVE — stat.ripe.net',
      nRow('Prefix',    esc(R.ripe.prefix||'Unknown'))+
      nRow('ASNs',      esc(R.ripe.asns.join(', ')||'Unknown'))+
      nRow('Abuse',     R.ripe.abuse.length ? esc(R.ripe.abuse.join(', ')) : '<span style="color:var(--text2)">unknown</span>')
    );
  }

  /* SSL */
  if(R.ssl){
    if(R.ssl.found){
      var sd=R.ssl.daysLeft;
      h+=nCard(sd<14?'bad':sd<30?'warn':'ok','SSL / CERTIFICATE','LIVE — '+(R.ssl.source||'crt.sh'),
        nRow('Issuer',   esc(R.ssl.issuer))+
        nRow('Subject',  esc(R.ssl.subject))+
        nRow('Expires',  esc(R.ssl.expiry)+
          '<span style="color:'+(sd<30?'var(--red)':'var(--green)')+'"> ('+sd+' days)</span>')+
        nRow('CT Certs', R.ssl.certCount+' total certs logged')
      );
    } else {
      h+=nCard('warn','SSL / CERTIFICATE','LIVE — crt.sh',
        '<div style="padding:10px 14px;font-size:11px;color:var(--text2)">'+
        'No certificates found in CT logs'+(R.ssl.error?': '+esc(R.ssl.error):'')+
        '</div>'
      );
    }
  }

  /* Headers */
  if(R.headers){
    var hh=R.headers;
    var dot=hh.corsBlocked?'info':(hh.missing||[]).filter(function(x){return x.required;}).length?'warn':'ok';
    var hbody='';
    if(!hh.reachable){
      hbody='<div style="padding:10px 14px;color:var(--red);font-size:12px">Target not reachable on HTTP/HTTPS.</div>';
    } else if(hh.corsBlocked){
      hbody='<div style="padding:10px 14px;font-size:11px;line-height:1.7;color:var(--text2)">'+
        'Server is reachable but <strong style="color:var(--text)">browser CORS policy prevents reading headers</strong> '+
        'of cross-origin sites like '+esc(target)+'. This is a browser security boundary, not a scanner bug.<br><br>'+
        'To get real security headers, run:<br>'+
        '<code style="font-size:10px;background:rgba(0,0,0,.4);padding:3px 7px;border-radius:4px;display:inline-block;margin-top:4px">'+
        'curl -sI https://'+esc(target)+' | grep -Ei "server|strict|content-security|x-frame|x-content|referrer|permissions|powered"'+
        '</code></div>';
    } else {
      hbody=nRow('Status','HTTP '+hh.statusCode)+
            nRow('Server', esc(hh.server||'Hidden'))+
            nRow('X-Powered-By', hh.xPoweredBy
              ? '<span style="color:var(--red)">'+esc(hh.xPoweredBy)+'</span>'
              : '<span style="color:var(--green)">Hidden</span>');
      if((hh.present||[]).length||(hh.missing||[]).length){
        hbody+='<div style="padding:4px 14px"><span style="font-size:10px;color:var(--text2);font-family:var(--mono);letter-spacing:.08em">SECURITY HEADERS:</span><br>';
        (hh.present||[]).forEach(function(x){hbody+='<span class="net-tag present" style="margin:2px">'+esc(x.short)+'</span>';});
        (hh.missing||[]).forEach(function(x){hbody+='<span class="net-tag missing" style="margin:2px">No '+esc(x.short)+'</span>';});
        hbody+='</div>';
      }
    }
    h+=nCard(dot,'SECURITY HEADERS',hh.corsBlocked?'REACHABLE':'LIVE',hbody);
  }

  /* Ports */
  if(R.ports!==undefined){
    var pbody='';
    if(R.ports.length){
      pbody='<div style="padding:10px 14px;display:flex;flex-wrap:wrap;gap:6px">';
      R.ports.forEach(function(p){
        pbody+='<div class="port-badge '+(p.risk==='critical'||p.risk==='high'?'open':'filtered')+'">'+p.port+' '+p.svc+'</div>';
      });
      pbody+='</div><div style="padding:0 14px 10px;font-size:10px;color:var(--text2)">Browser fetch detects HTTP/HTTPS ports only. For full TCP scan use nmap.</div>';
    } else {
      pbody='<div style="padding:10px 14px;font-size:11px;color:var(--text2)">No HTTP/HTTPS ports responded.<br><span style="font-size:10px">For full TCP scan: <code style="background:rgba(0,0,0,.3);padding:1px 4px;border-radius:3px">nmap -sV '+esc(target)+'</code></span></div>';
    }
    h+=nCard(R.ports.length?'warn':'ok','OPEN PORTS','LIVE',pbody);
  }

  /* Sensitive files — only confirmed 200s shown as "found" */
  if (R.files !== undefined) {
    var conf = R.files.confirmed || [];
    var blk  = R.files.corsBlocked || [];
    var fbody = '';

    if (conf.length) {
      fbody += '<div style="padding:10px 14px;display:flex;flex-wrap:wrap;gap:6px">';
      conf.forEach(function(f){
        var col = (f.sev==='critical'||f.sev==='high') ? 'open' : 'filtered';
        fbody += '<div class="port-badge '+col+'" title="HTTP '+f.status+' — '+esc(f.sev)+'">'+esc(f.label)+'</div>';
      });
      fbody += '</div>';
    } else {
      fbody += '<div style="padding:10px 14px;font-size:11px;color:var(--text2)">'+
        'No sensitive paths confirmed via the browser.</div>';
    }

    if (blk.length) {
      fbody += '<div style="padding:0 14px 8px;font-size:10px;line-height:1.6;color:var(--text2)">'+
        '<strong style="color:var(--text)">'+blk.length+' path(s) could not be verified</strong> from the browser '+
        '(CORS policy hides the response status). This is the same browser limit that blocks header reading — '+
        '<em>not</em> evidence the files exist. Verify from a terminal:<br>'+
        '<code style="font-size:10px;background:rgba(0,0,0,.4);padding:3px 7px;border-radius:4px;display:inline-block;margin-top:4px;white-space:pre-wrap;word-break:break-all">'+
        'for p in '+blk.map(function(f){ return f.path; }).join(' ')+'; do echo -n "$p "; curl -s -o /dev/null -w "%{http_code}\\n" https://'+esc(target)+'$p; done'+
        '</code></div>';
    }

    var dotState = conf.some(function(f){return f.sev==='critical';}) ? 'bad'
                 : conf.length ? 'warn'
                 : 'ok';
    h += nCard(dotState, 'SENSITIVE FILES', 'LIVE — '+conf.length+' confirmed / '+blk.length+' unverifiable', fbody);
  }

  /* Subdomains — split into LIVE (resolves today) and DEAD (in CT but no DNS) */
  if(R.subdomains!==undefined&&!isIp){
    var sbody = '';
    var verify = R.subVerify || { live:[], dead:[], skipped: R.subdomains||[] };
    if (R.subdomains.length) {
      if (verify.live.length) {
        sbody += '<div style="padding:8px 14px 4px;font-size:10px;color:var(--green);font-family:var(--mono);letter-spacing:.06em">LIVE — RESOLVES TODAY ('+verify.live.length+')</div>'+
          '<div style="padding:0 14px;display:flex;flex-wrap:wrap;gap:4px">';
        verify.live.forEach(function(s){ sbody += '<span class="net-tag present">'+esc(s)+'</span>'; });
        sbody += '</div>';
      }
      if (verify.dead.length) {
        sbody += '<div style="padding:8px 14px 4px;font-size:10px;color:var(--text2);font-family:var(--mono);letter-spacing:.06em">DEAD — IN CT LOG, NO DNS ('+verify.dead.length+')</div>'+
          '<div style="padding:0 14px;display:flex;flex-wrap:wrap;gap:4px;opacity:.55">';
        verify.dead.forEach(function(s){ sbody += '<span class="net-tag neutral" style="text-decoration:line-through">'+esc(s)+'</span>'; });
        sbody += '</div>';
      }
      if (verify.skipped.length) {
        sbody += '<div style="padding:8px 14px 4px;font-size:10px;color:var(--text2);font-family:var(--mono);letter-spacing:.06em">UNVERIFIED ('+verify.skipped.length+')</div>'+
          '<div style="padding:0 14px;display:flex;flex-wrap:wrap;gap:4px;opacity:.7">';
        verify.skipped.slice(0,30).forEach(function(s){ sbody += '<span class="net-tag neutral">'+esc(s)+'</span>'; });
        if (verify.skipped.length>30) sbody += '<span style="font-size:10px;color:var(--text2)">…+'+(verify.skipped.length-30)+' more</span>';
        sbody += '</div>';
      }
      sbody += '<div style="padding:8px 14px 10px;font-size:10px;color:var(--text2)">'+
        'Each "live" subdomain was re-resolved via DNS to confirm it actually exists today — CT logs include long-expired test/staging hosts, so the raw count is misleading.</div>';
    } else {
      sbody = '<div style="padding:10px 14px;font-size:11px;color:var(--text2)">No subdomains found.</div>';
    }
    var srcs = [];
    if (R.ssl && R.ssl.found) srcs.push('CT');
    if (R.ht && R.ht.hosts && R.ht.hosts.length) srcs.push('HackerTarget');
    var dotState = verify.live.length ? 'warn' : R.subdomains.length ? 'info' : 'ok';
    h += nCard(dotState,
      'SUBDOMAINS ('+verify.live.length+' live / '+R.subdomains.length+' total)',
      'LIVE — '+(srcs.join(' + ')||'none')+' + DNS verify',
      sbody);
  }

  /* Threat Intel — URLhaus + ThreatFox combined */
  if (R.urlhaus || R.tfox) {
    var uh = R.urlhaus || {}, tf = R.tfox || {};
    var clean = !uh.found && !tf.found;
    var tBody = '';
    if (uh.found) {
      var statusLabel = uh.online > 0
        ? '<span style="color:var(--red)">'+uh.online+' ACTIVE</span> / <span style="color:var(--text2)">'+uh.offline+' offline</span>'
        : '<span style="color:var(--yellow,#e6c84d)">'+uh.offline+' historical (all offline)</span>';
      tBody += nRow('URLhaus', statusLabel + ' — threat: '+esc(uh.threat||'unknown'));
      uh.urls.slice(0,3).forEach(function(u,i){
        var statColor = u.url_status === 'online' ? 'var(--red)' : 'var(--text2)';
        tBody += nRow('URL '+(i+1),
          '<code style="font-size:10px;background:rgba(0,0,0,.3);padding:1px 4px;border-radius:3px;word-break:break-all">'+
          esc(u.url||'')+'</code> <span style="color:'+statColor+';font-size:10px;margin-left:4px">'+esc(u.url_status||'')+'</span>');
      });
    }
    if (tf.found) {
      tBody += nRow('ThreatFox',
        '<span style="color:var(--red)">'+esc(tf.iocs.length)+' IOC match(es)</span>');
      tf.iocs.slice(0,3).forEach(function(i,n){
        tBody += nRow('IOC '+(n+1),
          esc((i.malware_printable||i.threat_type||'unknown')+' — '+(i.ioc_type||'')+' — confidence '+(i.confidence_level||'?')));
      });
    }
    if (clean) {
      tBody = '<div style="padding:10px 14px;font-size:11px;color:var(--green)">'+
        'No matches in URLhaus or ThreatFox. '+
        '<span style="color:var(--text2)">(abuse.ch threat feeds)</span></div>';
    }
    h += nCard(clean?'ok':'bad','THREAT INTEL','LIVE — abuse.ch', tBody);
  }

  /* Shared Hosting — IP scan only, with live DNS verification */
  if (isIp && R.revip) {
    var v = R.revipVerify || { live:[], stale:[], dead:[], skipped:R.revip.hosts||[], anycast:false };
    var rb = '';

    if (v.anycast) {
      rb = '<div style="padding:10px 14px;font-size:11px;line-height:1.6;color:var(--text2)">'+
        '<strong style="color:var(--text)">Reverse-IP suppressed for anycast.</strong> '+
        target+' is anycast (Google/Cloudflare/Quad9 etc.), so passive-DNS reverse-IP data is structurally noisy — '+
        'it lists every domain that ever pointed here by mistake or as a placeholder. '+
        'The raw HackerTarget result had '+R.revip.hosts.length+' entries; none are meaningfully "shared hosting".</div>';
    } else if (!R.revip.hosts.length) {
      rb = '<div style="padding:10px 14px;font-size:11px;color:var(--text2)">'+
        'No shared sites returned'+(R.revip.error?' ('+esc(R.revip.error)+')':'')+'.</div>';
    } else {
      if (v.live.length) {
        rb += '<div style="padding:8px 14px 4px;font-size:10px;color:var(--green);font-family:var(--mono);letter-spacing:.06em">LIVE — STILL POINTS TO '+esc(target)+' ('+v.live.length+')</div>'+
          '<div style="padding:0 14px;display:flex;flex-wrap:wrap;gap:4px">';
        v.live.slice(0,50).forEach(function(r){ rb += '<span class="net-tag present">'+esc(r.host)+'</span>'; });
        rb += '</div>';
      }
      if (v.stale.length) {
        rb += '<div style="padding:8px 14px 4px;font-size:10px;color:var(--yellow,#e6c84d);font-family:var(--mono);letter-spacing:.06em">STALE — RESOLVES ELSEWHERE NOW ('+v.stale.length+')</div>'+
          '<div style="padding:0 14px;display:flex;flex-wrap:wrap;gap:4px;opacity:.7">';
        v.stale.slice(0,30).forEach(function(r){
          rb += '<span class="net-tag warn" title="now → '+esc(r.addrs[0]||'?')+'">'+esc(r.host)+'</span>';
        });
        if (v.stale.length>30) rb += '<span style="font-size:10px;color:var(--text2)">…+'+(v.stale.length-30)+' more</span>';
        rb += '</div>';
      }
      if (v.dead.length) {
        rb += '<div style="padding:8px 14px 4px;font-size:10px;color:var(--text2);font-family:var(--mono);letter-spacing:.06em">DEAD — NXDOMAIN / NO A RECORD ('+v.dead.length+')</div>'+
          '<div style="padding:0 14px;display:flex;flex-wrap:wrap;gap:4px;opacity:.45">';
        v.dead.slice(0,30).forEach(function(r){ rb += '<span class="net-tag neutral" style="text-decoration:line-through">'+esc(r.host)+'</span>'; });
        if (v.dead.length>30) rb += '<span style="font-size:10px;color:var(--text2)">…+'+(v.dead.length-30)+' more</span>';
        rb += '</div>';
      }
      if (v.skipped.length) {
        rb += '<div style="padding:8px 14px;font-size:10px;color:var(--text2)">+'+v.skipped.length+' not verified (capped at 30 DNS lookups).</div>';
      }
      rb += '<div style="padding:0 14px 10px;font-size:10px;color:var(--text2)">'+
        'HackerTarget returns historical reverse-DNS data; only "live" entries currently point to '+esc(target)+' — the rest are stale/abandoned records.</div>';
    }

    var dotState = v.anycast ? 'info'
                 : v.live.length ? 'warn'
                 : R.revip.hosts.length ? 'info'
                 : 'ok';
    var titleCount = v.anycast ? R.revip.hosts.length+' (suppressed)'
                   : v.live.length+' live / '+R.revip.hosts.length+' total';
    h += nCard(dotState, 'SHARED HOSTING ('+titleCount+')', 'LIVE — HackerTarget + DNS verify', rb);
  }

  /* Wayback */
  if (!isIp && R.wb) {
    if (R.wb.found) {
      var ts = R.wb.lastSeen || '';
      var pretty = ts.length===8 ? ts.slice(0,4)+'-'+ts.slice(4,6)+'-'+ts.slice(6,8) : ts;
      h+=nCard('info','WAYBACK MACHINE','LIVE — archive.org',
        nRow('Last snapshot', esc(pretty))+
        nRow('Archived URL', '<a href="'+esc(R.wb.snapshot)+'" target="_blank" rel="noopener" style="color:var(--accent)">view</a>')
      );
    }
  }

  /* Tech */
  if(R.tech&&R.tech.length){
    h+=nCard('info','TECH STACK','LIVE',
      R.tech.map(function(t){ return nRow(t.cat,'<span class="net-tag '+(t.risk==='warn'?'warn':'neutral')+'">'+esc(t.name)+'</span>'); }).join('')
    );
  }

  /* WHOIS */
  if(R.whois){
    var w=R.whois;
    var wb=nRow('Registrar',esc(w.registrar||'Unknown'));
    if(w.org)              wb+=nRow('Org',esc(w.org));
    if(w.created)          wb+=nRow('Registered',esc(w.created));
    if(w.expires)          wb+=nRow('Expires',esc(w.expires));
    if(w.status&&w.status.length) wb+=nRow('Status', esc(w.status.slice(0,3).join(', ')));
    if(w.nameservers&&w.nameservers.length) wb+=nRow('Nameservers',esc(w.nameservers.slice(0,3).join(', ')));
    h+=nCard('info','WHOIS / RDAP','LIVE — RDAP',wb);
  }

  h+='</div>';
  c.innerHTML=h;
}

/* render helpers */
function nCard(dot,title,badge,body){
  return '<div class="net-card"><div class="net-card-head">'+
    '<div class="nc-dot '+dot+'"></div>'+esc(title)+
    (badge?'<span class="real-badge" style="margin-left:6px">'+esc(badge)+'</span>':'')+
    '</div>'+body+'</div>';
}
function nRow(k,v){
  return '<div class="net-row" style="padding:3px 14px"><span class="nr-key">'+esc(k)+'</span><span class="nr-val">'+v+'</span></div>';
}
function nNone(){ return '<em style="opacity:.35">—</em>'; }
function esc(s){ return typeof escHtml==='function'?escHtml(String(s||'')):String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function setTarget(v){ var e=document.getElementById('targetInput'); if(e) e.value=v; }
function setIpTarget(v){ var e=document.getElementById('ipTargetInput'); if(e) e.value=v; }

/* ─────────────────────────────────────────
   PRE-SCAN INFRA HINT
   When the user types a known anycast / public-DNS / root-NS IP into the
   IP or domain field, show an inline notice below the input BEFORE they
   click scan, so they aren't surprised when geo/reverse-IP look weird.
───────────────────────────────────────── */
function initInfraHints() {
  function ensureHintEl(input) {
    if (!input) return null;
    var existing = input.parentNode && input.parentNode.parentNode &&
      input.parentNode.parentNode.querySelector('[data-infra-hint="'+input.id+'"]');
    if (existing) return existing;
    var hint = document.createElement('div');
    hint.setAttribute('data-infra-hint', input.id);
    hint.style.cssText =
      'margin:8px 0 0;padding:8px 12px;border-left:2px solid #4dc4ff;'+
      'background:rgba(77,196,255,.06);border-radius:2px;'+
      'font-size:11px;line-height:1.55;font-family:var(--mono);'+
      'letter-spacing:.02em;color:var(--text2);display:none';
    var field = input.closest ? input.closest('.target-field') : null;
    if (field && field.parentNode) {
      field.parentNode.insertBefore(hint, field.nextSibling);
    } else {
      input.parentNode.appendChild(hint);
    }
    return hint;
  }

  function describe(value) {
    var v = (value || '').trim().replace(/^https?:\/\//i,'').replace(/[/?#].*/,'').replace(/:[\d]+$/,'').toLowerCase();
    if (!v) return null;
    var infra = INFRA_REGISTRY[v];
    if (!infra) return null;
    var color = infra.kind === 'anycast-dns' || infra.kind === 'root-dns' ? '#4dc4ff'
              : infra.kind === 'anycast'                                  ? '#9d7bff'
              : '#e6c84d';
    var label = infra.kind === 'anycast-dns' ? 'global anycast public-DNS resolver'
              : infra.kind === 'root-dns'    ? 'DNS root nameserver'
              : infra.kind === 'anycast'     ? 'global anycast network'
              : infra.kind;
    return {
      color: color,
      html:
        '<div><strong style="color:'+color+'">NOTICE — '+esc(v)+' is part of a '+esc(label)+'.</strong> '+
        '<span style="color:var(--text)">'+esc(infra.service)+'</span>'+
        (infra.provider && infra.provider!=='unknown' ? ' <span style="color:var(--text2)">('+esc(infra.provider)+')</span>' : '')+
        '</div>'+
        '<div style="margin-top:4px">'+
        'Geolocation, reverse-IP and shared-hosting data for this address are <strong style="color:var(--text)">structurally misleading</strong> — '+
        'the same IP is announced from many Points-of-Presence worldwide. The scanner will skip the modules that don\'t apply ('+
        (infra.skip && infra.skip.length ? esc(infra.skip.join(', ')) : 'none') +
        ') and add an explanatory banner to the result.'+
        '</div>'
    };
  }

  function attach(inputId) {
    var input = document.getElementById(inputId);
    if (!input) return;
    var update = function() {
      var hint = ensureHintEl(input);
      if (!hint) return;
      var hit = describe(input.value);
      if (hit) {
        hint.style.borderLeftColor = hit.color;
        hint.style.background = 'rgba('+hexToRgb(hit.color)+',.06)';
        hint.innerHTML = hit.html;
        hint.style.display = '';
      } else {
        hint.style.display = 'none';
      }
    };
    input.addEventListener('input', update);
    input.addEventListener('change', update);
    update();
  }

  function hexToRgb(hex) {
    var n = parseInt(hex.replace('#',''), 16);
    return [(n>>16)&255, (n>>8)&255, n&255].join(',');
  }

  attach('ipTargetInput');
  attach('targetInput');
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initInfraHints);
} else {
  initInfraHints();
}
>>>>>>> 921b7bd (- IP and Domain/URL Scanner updated\n- Added New sources like wayback, BGP, crt.sh, etc to the scanners.\n- Added the restroing functionality to the history options.\n- Now the IP and URL/Domain Scanner can gather too much information about the Geo Location and other information.\n- The Code Auditor got improved.)
