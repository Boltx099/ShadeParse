/**
 * ShadeParse — audits/csharp_audit.js
 * C# / ASP.NET-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var CS_SQL = [
  {re:/new\s+SqlCommand\s*\(\s*["'][^"']*["']\s*\+\s*\w+/gi, title:'SQL Injection — SqlCommand string concat (C#)', sev:'critical', desc:'String concat in SqlCommand → SQL injection.', fix:'var cmd = new SqlCommand("SELECT * FROM t WHERE id = @id", conn);\ncmd.Parameters.AddWithValue("@id", id);'},
];

var CS_XXE = [
  {re:/new\s+XmlDocument\s*\(\s*\)(?![^;]*\.XmlResolver\s*=\s*null)/gi, title:'XXE — XmlDocument without null XmlResolver (C#)', sev:'critical', desc:'XmlDocument without null resolver → XXE.', fix:'var doc = new XmlDocument();\ndoc.XmlResolver = null;\ndoc.LoadXml(xml);'},
];

var CS_CRYPTO = [
  {re:/MD5\.Create\s*\(\s*\)|new\s+MD5CryptoServiceProvider\s*\(\s*\)/gi, title:'Weak hashing — MD5 (C#)', sev:'high', desc:'MD5 is broken.', fix:'SHA256.Create()'},
  {re:/SHA1\.Create\s*\(\s*\)|new\s+SHA1CryptoServiceProvider\s*\(\s*\)/gi, title:'Weak hashing — SHA-1 (C#)', sev:'high', desc:'SHA-1 is deprecated.', fix:'SHA256.Create()'},
  {re:/DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider/gi, title:'Broken cipher — DES/3DES/RC2 (C#)', sev:'critical', desc:'DES, 3DES, RC2 are broken.', fix:'new AesGcm(key)'},
];

/**
 * runCsharpAudit(code) → Array of findings
 */
function runCsharpAudit(code) {
  var F = [];
  F = F.concat(runPats(code, CS_SQL,    'INJECT', 'inject-cs-sql', null));
  F = F.concat(runPats(code, CS_XXE,    'XXE',    'xxe-cs',        null));
  F = F.concat(runPats(code, CS_CRYPTO, 'CRYPTO', 'crypto-cs',     null));
  return F;
}
