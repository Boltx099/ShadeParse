/**
 * ShadeParse — audits/php_audit.js
 * PHP-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

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

/**
 * runPhpAudit(code) → Array of findings
 */
function runPhpAudit(code) {
  var F = [];
  F = F.concat(runPats(code, PHP_SQL,     'INJECT',  'inject-php-sql',  null));
  F = F.concat(runPats(code, PHP_CMD,     'INJECT',  'inject-php-cmd',  null));
  F = F.concat(runPats(code, PHP_XSS,     'XSS',     'xss-php',         null));
  F = F.concat(runPats(code, PHP_FILE,    'PATH',    'path-php',        null));
  F = F.concat(runPats(code, PHP_DESERIAL,'DESERIAL', 'deserial-php',   null));
  F = F.concat(runPats(code, PHP_CONFIG,  'CONFIG',  'config-php',      null));
  return F;
}
