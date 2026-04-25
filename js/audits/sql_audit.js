/**
 * ShadeParse — audits/sql_audit.js
 * Raw SQL-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var SQL_INJECT = [
  {re:/(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;]*\+\s*\w+/gi, title:'SQL Injection — dynamic SQL concatenation', sev:'critical', desc:'Direct string concatenation in SQL statement — user input can break query structure.', fix:'Use parameterized queries with ? or $N placeholders.'},
  {re:/EXEC(?:UTE)?\s+\(\s*@\w+\s*\)/gi, title:'SQL Injection — dynamic EXEC() in stored procedure', sev:'critical', desc:'EXEC() with variable argument in SQL → dynamic SQL injection.', fix:'Use sp_executesql with @params parameter.'},
];

/**
 * runSqlAudit(code) → Array of findings
 */
function runSqlAudit(code) {
  return runPats(code, SQL_INJECT, 'INJECT', 'inject-sql', null);
}
