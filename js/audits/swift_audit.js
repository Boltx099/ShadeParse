/**
 * ShadeParse — audits/swift_audit.js
 * Swift-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var SWIFT_SQL = [
  {re:/sqlite3_exec\s*\([^,]+,\s*(?:[^,]*\+|String\s*\(format:)/gi, title:'SQL Injection — sqlite3_exec() with concat (Swift)', sev:'critical', desc:'sqlite3_exec() with string interpolation/format → injectable.', fix:'Use prepared statements with sqlite3_prepare_v2.'},
  {re:/execute\s*\(\s*['\"]\s*\\\\?\(\w+\)/gi, title:'SQL Injection — execute() with Swift string interpolation', sev:'critical', desc:'String interpolation \\() in SQL → injectable.', fix:'Use ? placeholders and bind parameters.'},
];

/**
 * runSwiftAudit(code) → Array of findings
 */
function runSwiftAudit(code) {
  return runPats(code, SWIFT_SQL, 'INJECT', 'inject-swift-sql', null);
}
