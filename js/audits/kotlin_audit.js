/**
 * ShadeParse — audits/kotlin_audit.js
 * Kotlin / Android-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var KOTLIN_SQL = [
  {re:/rawQuery\s*\(\s*[\"'].*[\"']\s*\+/gi, title:'SQL Injection — rawQuery() + concat (Kotlin/Android)', sev:'critical', desc:'String concatenation in rawQuery() → SQL injection.', fix:'db.rawQuery("SELECT * FROM t WHERE id = ?", arrayOf(userInput))'},
  {re:/execSQL\s*\(\s*[\"'].*[\"']\s*\+/gi, title:'SQL Injection — execSQL() + concat (Kotlin/Android)', sev:'critical', desc:'String concat in execSQL() is injectable.', fix:'Use parameterized queries with ? placeholders.'},
];

/**
 * runKotlinAudit(code) → Array of findings
 */
function runKotlinAudit(code) {
  return runPats(code, KOTLIN_SQL, 'INJECT', 'inject-kotlin-sql', null);
}
