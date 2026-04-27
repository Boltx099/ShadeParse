/**
 * ShadeParse — audits/go_audit.js
 * Go-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

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

/**
 * runGoAudit(code) → Array of findings
 */
function runGoAudit(code) {
  var F = [];
  F = F.concat(runPats(code, GO_SQL,    'INJECT', 'inject-go-sql', null));
  F = F.concat(runPats(code, GO_CMD,    'INJECT', 'inject-go-cmd', null));
  F = F.concat(runPats(code, GO_CRYPTO, 'CRYPTO', 'crypto-go',     null));
  F = F.concat(runPats(code, GO_SSRF,   'SSRF',   'ssrf-go',       null));
  return F;
}
