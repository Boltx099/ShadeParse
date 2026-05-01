/**
 * ShadeParse — audits/shell_audit.js
 * Shell / Bash-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var SHELL_VULNS = [
  {re:/eval\s+["']?\$\{?\w+\}?/gi, title:'Code Injection — eval with variable (Shell)', sev:'critical', desc:'eval of variable → arbitrary code execution.', fix:'Never eval untrusted input.'},
  {re:/curl\s+[^|]*\|\s*(?:bash|sh)/gi, title:'RCE — curl pipe to shell', sev:'critical', desc:'curl | bash downloads and executes untrusted code.', fix:'Download first, verify checksum, then execute.'},
  {re:/wget\s+[^|]*\|\s*(?:bash|sh)/gi, title:'RCE — wget pipe to shell', sev:'critical', desc:'wget | bash executes untrusted remote code.', fix:'Download to file, verify checksum first.'},
  {re:/chmod\s+777\s+/gi, title:'Misconfiguration — chmod 777 (world-writable)', sev:'high', desc:'chmod 777 → world-writable files, any user can modify.', fix:'chmod 755 dirs, 644 files, 600 secrets.'},
  {re:/rm\s+-rf?\s+\$/gi, title:'Destructive — rm -rf with variable path', sev:'critical', desc:'rm -rf with variable path → accidental full deletion.', fix:'[ -n "$DIR" ] && rm -rf "$DIR"'},
  {re:/\bpassword\s*=\s*["'][^"']+["']/gi, title:'Hardcoded password in shell script', sev:'critical', desc:'Passwords in shell scripts appear in history and process lists.', fix:'PASSWORD=$DB_PASSWORD  # Use environment variables'},
];

/**
 * runShellAudit(code) → Array of findings
 */
function runShellAudit(code) {
  return runPats(code, SHELL_VULNS, 'SHELL', 'shell', null);
}
