/**
 * ShadeParse — audits/java_audit.js
 * Java-specific vulnerability patterns.
 * Requires: detectors.js (for runPats helper).
 */

'use strict';

var JAVA_SQL = [
  {re:/Statement\s*\.\s*execute(?:Query|Update)?\s*\(\s*["'].*["']\s*\+/gi, title:'SQL Injection — Statement + concatenation', sev:'critical', desc:'String concat in JDBC Statement → SQL injection.', fix:'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\nstmt.setInt(1, id);'},
  {re:/createQuery\s*\(\s*["'][^"']*["']\s*\+/gi, title:'SQL Injection — JPA createQuery() concat', sev:'critical', desc:'Dynamic JPQL with concat → injectable.', fix:'em.createQuery("SELECT e FROM Entity e WHERE e.id = :id").setParameter("id", id)'},
];

var JAVA_CMD = [
  {re:/Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*(?:\w+\s*\+|\breq\.|\brequest\.)/gi, title:'Command Injection — Runtime.exec() dynamic', sev:'critical', desc:'Runtime.exec() with user input → OS command execution.', fix:'Use ProcessBuilder with List<String> argument array.'},
  {re:/ScriptEngine\s*\.\s*eval\s*\(\s*(?:request\.getParameter|req\.getParameter)/gi, title:'Code Injection — ScriptEngine.eval() user input', sev:'critical', desc:'eval() on user-supplied scripts → arbitrary code execution.', fix:'Never evaluate user-controlled scripts.'},
];

var JAVA_XXE = [
  {re:/DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)(?![^;]*setFeature\s*\([^)]*"http:\/\/apache\.org\/xml\/features\/disallow-doctype-decl"[^)]*true)/gi, title:'XXE — DocumentBuilderFactory without DTD protection', sev:'critical', desc:'XML parsing without DOCTYPE disabled → XXE → file read, SSRF.', fix:'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'},
  {re:/SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)(?![^;]*setFeature)/gi, title:'XXE — SAXParserFactory without DTD protection', sev:'critical', desc:'SAXParser without DTD protection → XXE.', fix:'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'},
];

var JAVA_DESERIAL = [
  {re:/ObjectInputStream\s*\(\s*(?:request\.getInputStream|socket\.getInputStream|new\s+FileInputStream)/gi, title:'Insecure Deserialization — ObjectInputStream', sev:'critical', desc:'Java deserialization of untrusted streams → RCE via gadget chains.', fix:'Use JSON or whitelist-based deserialization.'},
];

var JAVA_CRYPTO = [
  {re:/MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']\s*\)/gi, title:'Weak hashing — MD5 or SHA-1 (Java)', sev:'high', desc:'MD5/SHA-1 are broken.', fix:'MessageDigest.getInstance("SHA-256")'},
  {re:/Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|Blowfish|RC4|AES\/ECB)[^"']*["']\s*\)/gi, title:'Broken cipher algorithm (Java)', sev:'critical', desc:'DES/AES-ECB/RC4 are broken or insecure.', fix:'Cipher.getInstance("AES/GCM/NoPadding")'},
  {re:/Math\.random\s*\(\s*\)/g, title:'Math.random() used for security (Java)', sev:'high', desc:'Math.random() is not cryptographically secure.', fix:'SecureRandom random = new SecureRandom();'},
];

/**
 * runJavaAudit(code) → Array of findings
 */
function runJavaAudit(code) {
  var F = [];
  F = F.concat(runPats(code, JAVA_SQL,     'INJECT',  'inject-java-sql',  null));
  F = F.concat(runPats(code, JAVA_CMD,     'INJECT',  'inject-java-cmd',  null));
  F = F.concat(runPats(code, JAVA_XXE,     'XXE',     'xxe-java',         null));
  F = F.concat(runPats(code, JAVA_DESERIAL,'DESERIAL', 'deserial-java',   null));
  F = F.concat(runPats(code, JAVA_CRYPTO,  'CRYPTO',  'crypto-java',      null));
  return F;
}
