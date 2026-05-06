## High-Value Feature Picks (Browser-Friendly, Fits Current Architecture)

Grouped by category with a quick “why” so you can prioritize efficiently.

## Visualization & Situational Awareness

- **Time histogram**  
  Bar chart above alerts table showing event volume per minute/hour (selectable bucket).  
  *Why:* Splunk-style view; instantly reveals spikes and trends.

- **Top-N widgets**  
  Panels for Top Source IPs / URLs / User-Agents / Status Codes / Countries.  
  Click any value → adds it as a KQL filter chip.  
  *Why:* Fast pivoting = better investigation workflow.

- **Geographic breakdown**  
  Bar list or simple SVG world heatmap using `ipGeo()` from `network.js`.  
  *Why:* Quick visual context of attack origins.

## Detection Coverage

- **MITRE ATT&CK mapping**  
  Tag alert types with technique IDs (e.g., T1190, T1110, T1059, T1595).  
  *Why:* Adds professional credibility and standardization.

- **Beacon detection**  
  Detect IPs hitting same endpoint at regular intervals (low jitter).  
  *Why:* Strong signal for C2 activity.

- **Honeypot path hits**  
  Flag access to sensitive paths like:  
  `/.env`, `/.git`, `/admin`, `/wp-login.php`, `/phpmyadmin`, `/api/v1/swagger`, `/.aws/credentials`  
  *Why:* Easy, high-confidence CRITICAL alerts.

- **DGA / suspicious-domain detection**  
  Flag high-entropy domains or unusual TLDs in DNS/proxy logs.  
  *Why:* Identifies malware C2 lookups.

- **Failed-login by username**  
  Track brute force per user (not just per IP).  
  *Why:* Detects distributed credential stuffing.

## Threat-Intel Enrichment

- **IP reputation enrichment**  
  Query URLhaus + ThreatFox (already in `network.js`).  
  Add “known-bad” badge to alerts.  
  *Why:* Immediate context without extra tooling.

- **Tor exit node check**  
  Fetch Tor exit list and match IPs.  
  *Why:* Highlights anonymized traffic sources.

- **ASN classification**  
  Label IPs as AWS / Cloudflare / Tor / Hetzner, etc.  
  *Why:* Analysts care about infra type (cloud vs residential).

## Workflow / UX Improvements

- **Saved searches**  
  Store KQL queries in `localStorage`.  
  *Why:* Speeds up repeated investigations.

- **Click-to-filter**  
  Click any field (IP, path, status, etc.) → auto-add KQL token.  
  *Why:* Kibana-style usability boost.

- **Time-range filter**  
  Options: 5m / 1h / 24h / custom.  
  *Why:* Core for timeline + alert scoping.

- **False-positive dismissal**  
  “Mark as benign” → greyed out + excluded from counts.  
  *Why:* Reduces alert fatigue.

- **Baseline diff**  
  Show “new alerts since last baseline.”  
  *Why:* Focus only on what changed.

- **Export alerts**  
  Download filtered alerts as CSV / JSON / SARIF.  
  *Why:* Reporting + integrations.

## Detection Engineering

- **Custom-rule editor**  
  UI for user-defined rules (regex + severity + MITRE ID).  
  Stored in `localStorage`.  
  *Why:* Flexible, no code changes required.

- **SIGMA-lite import**  
  Parse subset of SIGMA YAML rules.  
  *Why:* Unlocks large community detection library.

---

## Recommended Build Order (High Impact → Low Effort)

1. **Top-N widgets + click-to-filter**  
   → Immediate UX transformation

2. **Time histogram**  
   → Pairs naturally with time filtering

3. **MITRE ATT&CK mapping**  
   → Small effort, big credibility boost

4. **IP reputation enrichment**  
   → Reuse existing `network.js` logic

5. **Honeypot paths + beacon detection**  
   → Strong detection gains

6. **Saved searches + click-to-filter**  
   → Makes KQL actually usable

7. **Custom-rule editor**  
   → Long-term differentiation