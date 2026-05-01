/**
 * ShadeParse — lang-audit.js  (v6)
 * Language selection via single dropdown, obfuscation detection,
 * per-language audit dispatch, and diff-style vulnerable line highlighting.
 */

'use strict';

/* ══════════════════════════════════════════
   LANGUAGE SELECTION — single dropdown
══════════════════════════════════════════ */

window._selectedLang = null;

function setLangFromSelect(sel) {
  var val = sel.value;
  window._selectedLang = (val === 'auto') ? null : val;
  var label = sel.options[sel.selectedIndex].text;
  if (typeof showToast === 'function') {
    showToast('Language: ' + (val === 'auto' ? 'Auto-Detect' : label), 'success');
  }
}

// Legacy shim
function setLang(btn, langId) {
  window._selectedLang = (langId === 'auto') ? null : langId;
  var sel = document.getElementById('langSelect');
  if (sel) sel.value = langId;
  if (typeof showToast === 'function') {
    showToast('Language: ' + (langId === 'auto' ? 'Auto-Detect' : langId), 'success');
  }
}

/* ══════════════════════════════════════════
   PER-LANGUAGE AUDIT DISPATCH
══════════════════════════════════════════ */

function runLangAudit(code) {
  var lang = (typeof detectLanguage === 'function')
    ? detectLanguage(code)
    : (window._selectedLang || 'generic');

  var dispatch = {
    'js':         typeof runJsAudit         === 'function' ? runJsAudit         : null,
    'typescript': typeof runTypeScriptAudit === 'function' ? runTypeScriptAudit : null,
    'python':     typeof runPythonAudit     === 'function' ? runPythonAudit     : null,
    'php':        typeof runPhpAudit        === 'function' ? runPhpAudit        : null,
    'java':       typeof runJavaAudit       === 'function' ? runJavaAudit       : null,
    'go':         typeof runGoAudit         === 'function' ? runGoAudit         : null,
    'ruby':       typeof runRubyAudit       === 'function' ? runRubyAudit       : null,
    'cpp':        typeof runCppAudit        === 'function' ? runCppAudit        : null,
    'csharp':     typeof runCsharpAudit     === 'function' ? runCsharpAudit     : null,
    'rust':       typeof runRustAudit       === 'function' ? runRustAudit       : null,
    'shell':      typeof runShellAudit      === 'function' ? runShellAudit      : null,
    'kotlin':     typeof runKotlinAudit     === 'function' ? runKotlinAudit     : null,
    'swift':      typeof runSwiftAudit      === 'function' ? runSwiftAudit      : null,
    'sql':        typeof runSqlAudit        === 'function' ? runSqlAudit        : null,
  };

  var F = [];
  if (lang === 'generic') {
    Object.keys(dispatch).forEach(function(k) {
      if (dispatch[k]) F = F.concat(dispatch[k](code));
    });
  } else if (dispatch[lang]) {
    F = dispatch[lang](code);
  }
  return F;
}

/* ══════════════════════════════════════════
   OBFUSCATION & ENCODING DETECTION
══════════════════════════════════════════ */

function detectObfuscation(code) {
  if (!code || code.length < 20) return [];
  var F = [], lines = code.split('\n');

  function lineOf(idx) {
    var pos = 0;
    for (var i = 0; i < lines.length; i++) {
      pos += lines[i].length + 1;
      if (pos > idx) return i + 1;
    }
    return lines.length;
  }

  function hit(id, title, sev, idx, desc, fix) {
    var ln = lineOf(idx);
    return {
      id: id + '-' + ln, type: 'OBFUSC', title: title, sev: sev,
      loc: 'line ' + ln, line: ln,
      snippet: lines[ln - 1] ? lines[ln - 1].trim().slice(0, 120) : '',
      match:   lines[ln - 1] ? lines[ln - 1].trim().slice(0, 80)  : '',
      desc: desc,
      remediation: { text: desc, fix: fix || '// Deobfuscate and review' },
      confidence: 85, taint: null,
    };
  }

  function scan(pattern, id, title, sev, desc, fix) {
    var re = new RegExp(pattern.source, pattern.flags), m;
    while ((m = re.exec(code)) !== null) F.push(hit(id, title, sev, m.index, desc, fix));
  }

  scan(/eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)\s*\(/gi,
    'obf-eval-enc', 'eval() of encoded payload', 'critical',
    'eval() executing a base64/encoded payload — classic malware/backdoor pattern.',
    '// Decode manually: console.log(atob("...")) then inspect');

  scan(/(?:eval|Function)\s*\(\s*(?:eval|Function)\s*\(/gi,
    'obf-eval-chain', 'Chained eval/Function() calls', 'critical',
    'Nested eval/Function() hides code from static analysis.',
    '// Unpack and review inner payload');

  var b64re = /["'`]([A-Za-z0-9+/]{80,}={0,2})["'`]/g, bm;
  while ((bm = b64re.exec(code)) !== null) {
    var decoded = '';
    try { decoded = atob(bm[1]).slice(0, 60).replace(/[\x00-\x1f]/g, '.'); } catch(e) { continue; }
    F.push(hit('obf-b64', 'Suspicious Base64 payload (>80 chars)', 'high', bm.index,
      'Decoded preview: "' + decoded + '…"',
      '// Inspect: atob("' + bm[1].slice(0, 30) + '...")'));
  }

  scan(/(?:\\x[0-9a-fA-F]{2}){8,}/gi, 'obf-hex', 'Hex-encoded string (8+ chars)', 'high',
    'Dense hex escape — common obfuscation.', '// Decode hex manually');

  scan(/(?:\\u[0-9a-fA-F]{4}){6,}/gi, 'obf-uni', 'Dense unicode escape sequence', 'high',
    '6+ \\uXXXX escapes — JS obfuscation.', '// Run through a JS deobfuscator');

  scan(/\.map\s*\(\s*function\s*\(\s*\w+\s*\)\s*\{\s*return\s*\w+\s*\^\s*\d+\s*\}\)/gi,
    'obf-xor', 'XOR decode routine', 'critical',
    'Array.map() XOR — typical malware string decryption.', '// Execute XOR loop in isolation');

  scan(/\[\s*(?:\d+\s*,\s*){15,}\d+\s*\]\s*\.map\s*\(/gi,
    'obf-charcode-arr', 'Character-code array (hidden string)', 'high',
    '15+ char-code array hides strings.', '// String.fromCharCode(...[array])');

  scan(/String\.fromCharCode\s*\((?:\s*\d+\s*,){6,}/gi,
    'obf-fromcc', 'String.fromCharCode() with 6+ args', 'high',
    'Many fromCharCode() args hide string literals.', '// eval in console to reveal');

  scan(/function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/gi,
    'obf-packed', 'Packed JS (p,a,c,k,e,d)', 'critical',
    'dean.edwards packer — intentionally obfuscated JS.', '// Unpack at matthewfl.com/unPacker.html');

  scan(/eval\s*\(\s*(?:gzinflate|gzuncompress|str_rot13|base64_decode|hex2bin|gzdecode)\s*\(/gi,
    'obf-php', 'PHP eval(decode/decompress)', 'critical',
    'PHP eval() of decoded payload — webshell pattern.', '// echo base64_decode("..."); — never eval()');

  scan(/exec\s*\(\s*(?:__import__\s*\(\s*['"]base64['"]\s*\)|base64\s*\.\s*b64decode)/gi,
    'obf-py-b64', 'Python exec(base64.decode)', 'critical',
    'Python exec() of base64-decoded content.', '# Decode manually with base64.b64decode');

  scan(/exec\s*\(\s*(?:marshal\.loads|zlib\.decompress|gzip\.decompress)/gi,
    'obf-py-bin', 'Python exec(marshal/zlib)', 'critical',
    'exec() of compressed payload hides code.', '# Decompress outside exec() to inspect');

  scan(/(?:var\s+[a-zA-Z$_]\s*=\s*[a-zA-Z$_]\s*\[['"\d]+\]\s*[;,]){5,}/gi,
    'obf-array-subscript', 'Array-subscript obfuscation pattern', 'medium',
    '5+ single-char vars from array subscripts — obfuscator output.', '// Use js-beautify or deobfuscate.io');

  scan(/document\.write\s*\(\s*(?:unescape|decodeURIComponent|atob)\s*\(/gi,
    'obf-docwrite', 'document.write() of encoded content', 'critical',
    'Encoded document.write() injects hidden scripts.', '// Decode the argument, never write encoded content');

  return F;
}

/* ══════════════════════════════════════════
   DIFF-STYLE VULNERABLE LINE VIEW
══════════════════════════════════════════ */

function buildDiffCodeView(code, findings) {
  if (!code || !findings || !findings.length) return '';
  var lines = code.split('\n');
  var flagged = {};
  findings.forEach(function(f) {
    if (f.line && f.line > 0 && f.line <= lines.length) {
      if (!flagged[f.line]) flagged[f.line] = [];
      flagged[f.line].push(f);
    }
  });
  var flaggedLineNums = Object.keys(flagged).map(Number);
  if (!flaggedLineNums.length) return '';

  var showSet = {};
  flaggedLineNums.forEach(function(ln) {
    for (var i = Math.max(1, ln - 2); i <= Math.min(lines.length, ln + 2); i++) showSet[i] = true;
  });
  var showLines = Object.keys(showSet).map(Number).sort(function(a, b) { return a - b; });

  var html = '<div class="diff-view"><div class="diff-header">'
    + '<span class="diff-title">⚑ VULNERABLE LINE DIFF — ' + flaggedLineNums.length + ' line(s) flagged</span>'
    + '<span class="diff-legend"><span class="diff-vuln-badge">— VULNERABLE</span></span>'
    + '</div><div class="diff-body">';

  var lastShown = 0;
  showLines.forEach(function(ln) {
    if (lastShown > 0 && ln > lastShown + 1) {
      html += '<div class="diff-line diff-omit"><span class="diff-ln">···</span>'
        + '<span class="diff-pfx"> </span>'
        + '<span class="diff-txt" style="opacity:.45;font-style:italic"> ··· '
        + (ln - lastShown - 1) + ' lines omitted ···</span></div>';
    }
    lastShown = ln;
    var lineText = lines[ln - 1] || '';
    var isVuln = !!flagged[ln];
    html += '<div class="' + (isVuln ? 'diff-line diff-vuln' : 'diff-line diff-ctx') + '">'
      + '<span class="diff-ln">' + ln + '</span>'
      + '<span class="diff-pfx">' + (isVuln ? '-' : ' ') + '</span>'
      + '<span class="diff-txt">' + escHtml(lineText) + '</span>';
    if (isVuln) {
      var labels = flagged[ln].map(function(f) { return f.title; });
      html += '<span class="diff-vuln-label" title="' + escHtml(labels.join(' | ')) + '">'
        + '⚑ ' + escHtml(labels[0])
        + (labels.length > 1 ? ' (+' + (labels.length - 1) + ')' : '') + '</span>';
    }
    html += '</div>';
  });
  html += '</div></div>';
  return html;
}

/* ══════════════════════════════════════════
   HOOK INTO SCANNER
══════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', function() {
  var sel = document.getElementById('langSelect');
  if (sel && window._selectedLang) sel.value = window._selectedLang;

  var _origRunAudit = window.runAudit;

  window.runAudit = function(state, cfg) {
    var codeEl = document.getElementById('codeInput');
    var code   = codeEl ? codeEl.value : '';

    var _origDetect = window.detectLanguage;
    if (window._selectedLang && typeof window.detectLanguage === 'function') {
      window.detectLanguage = function() { return window._selectedLang; };
    }

    if (typeof _origRunAudit === 'function') _origRunAudit(state, cfg);

    if (window._selectedLang) window.detectLanguage = _origDetect;

    var attempts = 0;
    var poll = setInterval(function() {
      attempts++;
      var progEl = document.getElementById('progFill') || document.querySelector('.progress-fill');
      var done   = (progEl && parseFloat(progEl.style.width) >= 99);

      if (done || attempts > 60) {
        clearInterval(poll);

        // Run per-language auditors (from split files)
        if (code && typeof runLangAudit === 'function') {
          var langFinds = runLangAudit(code);
          if (langFinds.length) {
            var seen1 = new Set((state.allFindings || []).map(function(f) { return f.id; }));
            langFinds.forEach(function(f) { if (!seen1.has(f.id)) state.allFindings.push(f); });
          }
        }

        // Obfuscation detection
        if (code && typeof detectObfuscation === 'function') {
          var obfFinds = detectObfuscation(code);
          if (obfFinds.length) {
            var seen2 = new Set((state.allFindings || []).map(function(f) { return f.id; }));
            obfFinds.forEach(function(f) { if (!seen2.has(f.id)) state.allFindings.push(f); });
          }
        }

        if ((state.allFindings || []).length) {
          if (typeof sortBySeverity === 'function') state.allFindings = sortBySeverity(state.allFindings);
          if (typeof updateMetrics  === 'function') updateMetrics(state.allFindings);
          if (typeof showRiskScore  === 'function') showRiskScore(state.allFindings);
          if (typeof buildSevPills  === 'function') buildSevPills(state, cfg || APP.cfg);
          if (typeof renderFindings === 'function') renderFindings(state, cfg || APP.cfg);
        }

        injectDiffView(code, state.allFindings || []);
      }
    }, 200);
  };
});

function injectDiffView(code, findings) {
  var diffHtml = buildDiffCodeView(code, findings);
  var wrap = document.getElementById('diffCodeWrap');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.id = 'diffCodeWrap';
    wrap.style.marginTop = '16px';
    var findArea = document.getElementById('findingsArea');
    if (findArea && findArea.parentNode) {
      findArea.parentNode.insertBefore(wrap, findArea.nextSibling);
    } else {
      var scanLeft = document.querySelector('.scanner-left');
      if (scanLeft) scanLeft.appendChild(wrap);
    }
  }
  wrap.innerHTML = diffHtml;
}
