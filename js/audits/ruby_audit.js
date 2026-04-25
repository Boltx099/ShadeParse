/**
 * ShadeParse — audits/ruby_audit.js
 * Ruby / Rails-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var RUBY_SQL = [
  {re:/where\s*\(\s*["'][^"']*#\{/gi, title:'SQL Injection — ActiveRecord where() interpolation', sev:'critical', desc:'String interpolation in where() → SQL injection.', fix:'User.where("name = ?", params[:name])'},
  {re:/find_by_sql\s*\(\s*["'][^"']*#\{/gi, title:'SQL Injection — find_by_sql() interpolation', sev:'critical', desc:'find_by_sql with interpolation → injectable.', fix:'User.find_by_sql(["SELECT * FROM t WHERE id = ?", id])'},
];

var RUBY_CMD = [
  {re:/`[^`]*#\{[^}]*(?:params|request)\./gi, title:'Command Injection — backtick exec + params', sev:'critical', desc:'Ruby backtick with user params → command injection.', fix:'Use Open3.capture3 with argument array.'},
  {re:/system\s*\(\s*["'][^"']*#\{[^}]*(?:params|request)\./gi, title:'Command Injection — system() interpolation', sev:'critical', desc:'system() with interpolated params → injection.', fix:'system("command", sanitized_arg)'},
  {re:/eval\s*\(\s*(?:params\[|request\.)/gi, title:'Code Injection — eval() user input (Ruby)', sev:'critical', desc:'eval() on user params → arbitrary Ruby execution.', fix:'Never eval() user input.'},
];

var RUBY_XSS = [
  {re:/\.html_safe\s*$/gm, title:'XSS — .html_safe bypasses Rails auto-escaping', sev:'high', desc:'.html_safe disables escaping. Dangerous with user input.', fix:'Use h() or ERB::Util.html_escape() on user strings.'},
  {re:/raw\s*\(\s*(?:params\[|@\w+)/gi, title:'XSS — raw() with user-controlled variable (Rails)', sev:'high', desc:'raw() outputs unescaped HTML. Never use with user input.', fix:'Use default Rails escaping: <%= @variable %>'},
];

var RUBY_DESERIAL = [
  {re:/Marshal\.load\s*\(\s*(?:params|request|Base64\.decode)/gi, title:'Insecure Deserialization — Marshal.load()', sev:'critical', desc:'Marshal.load() with untrusted data → arbitrary code.', fix:'Use JSON.parse() for data interchange.'},
  {re:/YAML\.load\s*\(\s*(?:params|request|File\.read)/gi, title:'Insecure Deserialization — YAML.load() unsafe', sev:'critical', desc:'YAML.load() with user data → arbitrary Ruby via Psych.', fix:'YAML.safe_load(data)'},
];

/**
 * runRubyAudit(code) → Array of findings
 */
function runRubyAudit(code) {
  var F = [];
  F = F.concat(runPats(code, RUBY_SQL,     'INJECT',  'inject-ruby-sql', null));
  F = F.concat(runPats(code, RUBY_CMD,     'INJECT',  'inject-ruby-cmd', null));
  F = F.concat(runPats(code, RUBY_XSS,     'XSS',     'xss-ruby',        null));
  F = F.concat(runPats(code, RUBY_DESERIAL,'DESERIAL', 'deserial-ruby',   null));
  return F;
}
