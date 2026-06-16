# ShadeParse

Advanced static source code auditing dashboard built for security researchers, bug hunters, and developers. ShadeParse helps identify exposed secrets, insecure logic, weak cryptography, dangerous sinks, suspicious endpoints, and other high-risk patterns directly from source code.

---

## Overview

ShadeParse is a browser-based static security analysis tool designed to inspect code snippets, bundled JavaScript, or reconstructed source files through a clean dashboard interface. It focuses purely on source code auditing and vulnerability pattern detection.

---
## Trial Demo 
- Access Here: https://shade-parse.vercel.app/
- Login with: Username:`getsethack` | Password:`getsethack` 

## Features

* Static source code auditing
* Hardcoded secret detection
* API keys, JWT secrets, tokens, passwords
* XSS sink detection
* `innerHTML`, `eval()`, `document.write()`
* Weak cryptography detection
* MD5, SHA1, insecure randomness
* Endpoint discovery
* `/admin`, `/debug`, `/internal`, private routes
* Logic flaw detection
* Client-side auth bypass patterns
* Risk scoring engine
* Severity filters
* Search findings
* Export reports
* JSON / CSV / SARIF
* Drag and drop file support
* Animated pipeline scanner
* Modular architecture

---

## Screenshots

```text
/assets/dashboard.png
/assets/findings.png
/assets/pipeline.png
```

---

## Project Structure

```bash
ShadeParse/
├── index.html
├── README.md
├── css/
│   └── style.css
└── js/
    ├── app.js
    ├── ui.js
    ├── scanner.js
    ├── detectors.js
    ├── pipeline.js
    ├── export.js
    ├── samples.js
    └── utils.js
```

---

## Detection Categories

### Secrets

* AWS keys
* Stripe keys
* Firebase configs
* JWT secrets
* Passwords
* Database connection strings

### Client-side Security

* DOM XSS
* Eval abuse
* Dangerous HTML injection

### Weak Crypto

* MD5
* SHA1
* Math.random token generation

### Application Logic

* LocalStorage auth trust
* Debug bypasses
* Hidden admin routes

### Supply Chain

* Suspicious packages
* Risky dependencies

---

## Installation

Clone repository:

```bash
git clone https://github.com/Boltx099/ShadeParse.git
cd ShadeParse
```

Run locally:

```bash
open index.html
```

Or use VS Code Live Server.

---

## Usage

1. Open ShadeParse
2. Paste source code or upload a file
3. Click **Run Audit**
4. Review findings
5. Filter by severity
6. Export report

---

## Export Formats

* JSON
* CSV
* SARIF

---

## Roadmap

* AI remediation engine
* Custom regex rules
* Team collaboration mode
* CLI version
* Python backend scanner
* GitHub repository scanning
* CI/CD integration

---

## Why ShadeParse

Many scanners are either too complex, too expensive, or too noisy. ShadeParse focuses on speed, clarity, and practical findings for researchers and developers.

---

## Built With

* HTML5
* CSS3
* Vanilla JavaScript

---

## Ideal For

* Bug bounty hunters
* Pentesters
* Security students
* Developers
* Code reviewers

---

# Contribution Policy

Thank you for your interest in improving ShadeParse.

ShadeParse is a privately owned proprietary project. Contributions are reviewed and accepted only at the sole discretion of the project owner.

## How to Contribute

If you would like to contribute:

* Open an issue describing the bug, feature request, or improvement
* Submit a pull request with clear documentation of changes
* Keep code clean, secure, and consistent with the project architecture
* Ensure your submission does not include third-party copyrighted code

## Review Process

All contributions are manually reviewed. Submission of a pull request does not guarantee acceptance, merge, release, or attribution.

The project owner may modify, reject, defer, or remove any contribution for any reason.

## Contributor License

By submitting code, documentation, designs, or other materials to this repository, you agree that:

* You have the legal right to submit the contribution
* The contribution is your original work or properly authorized
* You grant the project owner a perpetual, worldwide, irrevocable, royalty-free right to use, modify, distribute, sublicense, and commercialize the contribution as part of ShadeParse
* You retain ownership of your original contribution unless otherwise agreed in writing

## Security Contributions

Responsible disclosure of vulnerabilities is encouraged. Please privately report security issues to the repository owner before public disclosure.

## Code of Conduct

Contributors are expected to communicate professionally and respectfully.

## Final Authority

All technical, architectural, licensing, and roadmap decisions remain with the project owner.



