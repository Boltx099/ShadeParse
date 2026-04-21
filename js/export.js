/**
 * ShadeParse — export.js
 * JSON / CSV / SARIF export.
 * FIXED: was using window.allFindings (always empty).
 *        Now reads from APP.state.allFindings.
 */

'use strict';

function downloadFile(name, content, type) {
  var blob = new Blob([content], { type: type });
  var url  = URL.createObjectURL(blob);
  var a    = document.createElement('a');
  a.href     = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function() { URL.revokeObjectURL(url); }, 500);
}

function getFindings() {
  /* FIXED: was window.allFindings — always [] because it was never populated */
  return (typeof APP !== 'undefined' && APP.state && APP.state.allFindings) ? APP.state.allFindings : [];
}

/* ─── SARIF ─── */

function buildSarif() {
  var el = document.getElementById('sarifPre');
  if (!el) return;

  var findings = getFindings();
  if (!findings.length) {
    el.textContent = 'Run a scan first to generate SARIF output.';
    return;
  }

  var uniqueRules = [];
  var seen = {};
  findings.forEach(function(f) {
    if (!seen[f.id]) {
      seen[f.id] = true;
      uniqueRules.push({
        id: f.id,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription:  { text: f.desc || f.title },
        defaultConfiguration: {
          level: (f.sev === 'critical' || f.sev === 'high') ? 'error' : 'warning',
        },
      });
    }
  });

  var sarif = {
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ShadeParse',
          version: '4.0.0',
          rules: uniqueRules,
        },
      },
      results: findings.map(function(f) {
        return {
          ruleId: f.id,
          level: (f.sev === 'critical' || f.sev === 'high') ? 'error' : 'warning',
          message: { text: f.desc || f.title },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: '<source>' },
              region: {
                startLine: f.line || 1,
                snippet: { text: f.snippet || '' },
              },
            },
          }],
        };
      }),
    }],
  };

  el.textContent = JSON.stringify(sarif, null, 2);
}

function copySarif() {
  var el = document.getElementById('sarifPre');
  if (!el || !el.textContent || el.textContent === 'Run a scan first to generate SARIF output.') return;
  navigator.clipboard.writeText(el.textContent).then(function() {
    showToast('SARIF copied to clipboard.', 'success');
  }).catch(function() {
    showToast('Clipboard blocked by browser.', 'warn');
  });
}

function dlSarif() {
  var el = document.getElementById('sarifPre');
  if (!el || !el.textContent || el.textContent.indexOf('Run a scan') === 0) {
    showToast('Run a scan first.', 'warn');
    return;
  }
  downloadFile('shadeparse-findings.sarif', el.textContent, 'application/json');
  showToast('SARIF downloaded.', 'success');
}

/* ─── JSON ─── */

function exportJSON() {
  var findings = getFindings();
  if (!findings.length) {
    showToast('Run a scan first.', 'warn');
    return;
  }
  downloadFile(
    'shadeparse-findings-' + Date.now() + '.json',
    JSON.stringify(findings, null, 2),
    'application/json'
  );
  showToast('JSON exported (' + findings.length + ' findings).', 'success');
}

/* ─── CSV ─── */

function csvEscape(v) {
  return '"' + String(v).replace(/"/g, '""') + '"';
}

function exportCSV() {
  var findings = getFindings();
  if (!findings.length) {
    showToast('Run a scan first.', 'warn');
    return;
  }

  var rows = [['ID','Type','Title','Severity','Location','Line','Confidence','Description'].join(',')];

  findings.forEach(function(f) {
    rows.push([
      csvEscape(f.id),
      csvEscape(f.type),
      csvEscape(f.title),
      csvEscape(f.sev),
      csvEscape(f.loc),
      csvEscape(f.line || ''),
      csvEscape((f.confidence || 0) + '%'),
      csvEscape(f.desc || ''),
    ].join(','));
  });

  downloadFile(
    'shadeparse-findings-' + Date.now() + '.csv',
    rows.join('\r\n'),
    'text/csv'
  );
  showToast('CSV exported (' + findings.length + ' rows).', 'success');
}
