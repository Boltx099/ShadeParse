/**
 * ShadeParse — audits/cpp_audit.js
 * C / C++-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var CPP_VULNS = [
  {re:/\bgets\s*\(\s*\w+/gi, title:'Buffer Overflow — gets() (no bounds check)', sev:'critical', desc:'gets() has no bounds checking → unconditionally vulnerable to overflow.', fix:'fgets(buf, sizeof(buf), stdin);'},
  {re:/\bstrcpy\s*\(\s*\w+\s*,/gi, title:'Buffer Overflow — strcpy() no bounds check', sev:'critical', desc:'strcpy() does not check buffer length → stack/heap overflow.', fix:'strncpy(dst, src, sizeof(dst) - 1); dst[sizeof(dst)-1] = 0;'},
  {re:/\bsprintf\s*\(\s*\w+\s*,\s*\w+\s*,/gi, title:'Buffer Overflow — sprintf() potential overflow', sev:'high', desc:'sprintf() without bounds check can overflow destination.', fix:'snprintf(buf, sizeof(buf), "%s", src);'},
  {re:/\bscanf\s*\(\s*["']%s["']/gi, title:'Buffer Overflow — scanf("%s") unbounded read', sev:'critical', desc:'scanf %s reads unlimited input → overflow.', fix:'scanf("%255s", buf);'},
  {re:/\bstrcat\s*\(\s*\w+\s*,/gi, title:'Buffer Overflow — strcat() no bounds check', sev:'high', desc:'strcat() does not validate buffer capacity.', fix:'strncat(dst, src, sizeof(dst) - strlen(dst) - 1);'},
  {re:/\bsystem\s*\(\s*\w+/gi, title:'Command Injection — system() with variable', sev:'critical', desc:'system() with variable may enable command injection.', fix:'Use execve() with argv array.'},
  {re:/\bprintf\s*\(\s*\w+\s*\)/gi, title:'Format String Vulnerability — printf(userStr)', sev:'critical', desc:'printf() with user format string → arbitrary read/write.', fix:'printf("%s", user_string);'},
];

/**
 * runCppAudit(code) → Array of findings
 */
function runCppAudit(code) {
  return runPats(code, CPP_VULNS, 'BUFFER', 'buffer-c', null);
}
