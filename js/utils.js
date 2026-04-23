/**
 * ShadeParse — utils.js
 *
 * FIXED:
 *  - Added missing escHtml alias, sortBySeverity, escHl safe version.
 *  - Severity colors consolidated here as SP_SEV_COLORS — single source of truth.
 *    scanner.js and ui.js read from this object instead of re-defining their own.
 */

'use strict';

/* ─── HTML ESCAPING ─── */

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* escHtml used throughout — aliased here as the canonical name */
var escHtml = esc;

/* ─── SNIPPET HELPERS ─── */

function lineOf(code, idx) {
  return code.slice(0, idx).split('\n').length;
}

function snip(code, line) {
  var snipLen = (typeof APP !== 'undefined' && APP.cfg) ? APP.cfg.snipLen : 120;
  return (code.split('\n')[line - 1] || '').trim().slice(0, snipLen);
}

function escHl(snippet, match) {
  var s = esc(snippet || '');
  var m = esc(match || '');
  if (!m) return s;
  var idx = s.indexOf(m);
  if (idx < 0) return s;
  return s.slice(0, idx) + '<span class="hl">' + m + '</span>' + s.slice(idx + m.length);
}

/* ─── SEVERITY COLORS — single source of truth ───
   Import via SP_SEV_COLORS[sev].fg / .bg / .bd everywhere.
   Do not re-define inline severity color maps in scanner.js or ui.js. */

var SP_SEV_COLORS = {
  critical: { fg: '#ff4d6a', bg: 'rgba(255,77,106,.1)',  bd: 'rgba(255,77,106,.25)' },
  high:     { fg: '#ff6b47', bg: 'rgba(255,107,71,.1)',  bd: 'rgba(255,107,71,.25)' },
  medium:   { fg: '#f5a623', bg: 'rgba(245,166,35,.1)',  bd: 'rgba(245,166,35,.25)' },
  low:      { fg: '#2ecc89', bg: 'rgba(46,204,137,.1)',  bd: 'rgba(46,204,137,.25)' },
  info:     { fg: '#4f8fff', bg: 'rgba(79,143,255,.1)',  bd: 'rgba(79,143,255,.25)' },
};

/* ─── COLOR HELPERS ─── */

function tc(t) {
  return {
    SECRET:'#ff2d55', ENDPOINT:'#3d9eff', XSS:'#ff6030',  PROTO:'#9b5fff',
    CRYPTO:'#00d4b8', SUPPLY:'#ffc840',   LOGIC:'#ff3a9d', CONFIG:'#6878a8',
    CRED:'#ff5c00',   INJECT:'#e040fb',   STORAGE:'#00bcd4',
    DESERIAL:'#ff1744', PATH:'#ff6e40',   SSRF:'#d500f9'
  }[t] || '#6878a8';
}

function tbg(t) {
  return {
    SECRET:'rgba(255,45,85,.12)',    ENDPOINT:'rgba(61,158,255,.12)',  XSS:'rgba(255,96,48,.12)',
    PROTO:'rgba(155,95,255,.12)',    CRYPTO:'rgba(0,212,184,.12)',      SUPPLY:'rgba(255,200,64,.12)',
    LOGIC:'rgba(255,58,157,.12)',    CONFIG:'rgba(104,120,168,.1)',
    CRED:'rgba(255,92,0,.12)',       INJECT:'rgba(224,64,251,.12)',     STORAGE:'rgba(0,188,212,.12)',
    DESERIAL:'rgba(255,23,68,.12)', PATH:'rgba(255,110,64,.12)',       SSRF:'rgba(213,0,249,.12)'
  }[t] || 'rgba(120,120,120,.1)';
}

function sc(s) {
  return (SP_SEV_COLORS[s] && SP_SEV_COLORS[s].fg) || '#6878a8';
}

function sevColor(s) { return sc(s); }
function typeColor(t) { return tc(t); }
function typeBg(t)    { return tbg(t); }

/* ─── RISK SCORING ─── */

function computeRiskScore(findings) {
  if (!findings || !findings.length) return 0;
  var raw = findings.reduce(function(acc, f) {
    var sevW  = { critical: 20, high: 10, medium: 4, low: 1, info: 0 }[f.sev] || 0;
    var conf  = (typeof f.confidence === 'number') ? f.confidence / 100 : 0.8;
    return acc + sevW * conf;
  }, 0);
  var score = Math.round(100 * (1 - Math.exp(-raw / 40)));
  return Math.max(0, Math.min(100, score));
}

function riskColor(score) {
  if (score >= 70) return 'var(--red)';
  if (score >= 40) return 'var(--amber)';
  return 'var(--green)';
}

/* ─── SORT BY SEVERITY ─── */

var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function sortBySeverity(findings) {
  if (!findings || !findings.length) return [];
  return findings.slice().sort(function(a, b) {
    var ao = (SEV_ORDER[a.sev] !== undefined) ? SEV_ORDER[a.sev] : 5;
    var bo = (SEV_ORDER[b.sev] !== undefined) ? SEV_ORDER[b.sev] : 5;
    return ao - bo;
  });
}

/* ─── MISC ─── */

function sleep(ms) {
  return new Promise(function(r) { setTimeout(r, ms); });
}