/**
 * ShadeParse — audits/rust_audit.js
 * Rust-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var RUST_VULNS = [
  {re:/unsafe\s*\{[^}]*\bptr::/gi, title:'Unsafe Code — raw pointer dereference (Rust)', sev:'high', desc:'Raw pointer ops in unsafe bypass Rust safety.', fix:'Consider safe alternatives. Document safety invariants thoroughly.'},
  {re:/\.unwrap\(\)/g, title:'Error Handling — unwrap() panics on None/Err (Rust)', sev:'medium', desc:'.unwrap() crashes on None/Err → denial of service.', fix:'Use ? operator, match, or .unwrap_or_else(|e| ...).'},
  {re:/from_utf8_unchecked|from_raw_parts\s*\(|std::mem::transmute/gi, title:'Unsafe Memory — unchecked cast (Rust)', sev:'high', desc:'Unchecked memory casts → UB, corruption, RCE.', fix:'Use safe alternatives: from_utf8()?.'},
];

/**
 * runRustAudit(code) → Array of findings
 */
function runRustAudit(code) {
  return runPats(code, RUST_VULNS, 'RUST', 'rust', null);
}
