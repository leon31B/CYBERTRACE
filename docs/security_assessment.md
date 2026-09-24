# Security Assessment Report — CYBERTRACE

## 1. Laboratory Overview
- **Project Name:** CYBERTRACE — Digital Investigation & Web Security Assessment Lab
- **Environment:** Localhost Educational Environment (`127.0.0.1:5000`)
- **Assessment Scope:** Web Application Security, Vulnerability Demonstration, Defensive Engineering

---

## 2. Assessment Findings & Verification Summary

| Finding ID | Vulnerability Category | OWASP 2021 Reference | Status | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | SQL Injection (SQLi) | A03:2021 — Injection | **MITIGATED** | Parameterized query (`cursor.execute(..., (?))`) prevents SQL parsing of payload `' OR '1'='1`. |
| **SEC-02** | Cross-Site Scripting (XSS) | A03:2021 — Injection | **MITIGATED** | Jinja2 contextual HTML entity escaping converts `<` and `>` into `&lt;` and `&gt;`. |
| **SEC-03** | Cross-Site Request Forgery (CSRF) | A01:2021 — Broken Access Control | **MITIGATED** | Cryptographic Synchronizer CSRF tokens validated on all state-changing POST endpoints. |
| **SEC-04** | Broken Access Control | A01:2021 — Broken Access Control | **MITIGATED** | Server-side `@role_required(['ADMIN'])` rejects unauthorized role requests with HTTP 403. |
| **SEC-05** | Sensitive Information Disclosure | A05:2021 — Security Misconfiguration | **MITIGATED** | Production `@app.errorhandler` serves generic templates; diagnostic traces logged to server console only. |

---

## 3. Detailed Vulnerability Analyses

### 3.1 SQL Injection Analysis
- **Vulnerable Pattern:** String concatenation (`f"SELECT ... WHERE code = '{input}'"`).
- **Observed Behavior:** An input of `' OR '1'='1` breaks query structure, causing all confidential rows to be returned.
- **Defense Implemented:** Parameterized queries via SQLite prepared statements. Inputs are passed in the parameter tuple, guaranteeing they are interpreted as literal string constants rather than executable SQL syntax.

### 3.2 Cross-Site Scripting (XSS) Analysis
- **Vulnerable Pattern:** Direct unescaped output rendering (`{{ input | safe }}`).
- **Observed Behavior:** Injected `<script>` and `<img onerror=...>` tags execute in the browser DOM.
- **Defense Implemented:** Standard Jinja2 autoescaping (`{{ input }}`). Special characters are translated into harmless HTML entities before insertion into the response stream.

### 3.3 Cross-Site Request Forgery (CSRF) Analysis
- **Vulnerable Pattern:** State-changing POST endpoint relying only on browser session cookies without an anti-forgery token.
- **Observed Behavior:** External or cross-origin submissions alter user department without authorization.
- **Defense Implemented:** Synchronizer Token Pattern. The application creates a unique cryptographically random token per session and verifies that each incoming POST request contains an identical token.

### 3.4 Broken Access Control Analysis
- **Vulnerable Pattern:** Client-side only hiding of navigation links; lack of route-level authorization checks.
- **Observed Behavior:** An Analyst directly navigates to administrative endpoints and accesses classified files.
- **Defense Implemented:** Server-side RBAC decorator (`@role_required`). Requests are intercepted prior to route execution, checking the active role and returning HTTP 403 Forbidden when unauthorized.

### 3.5 Sensitive Information Disclosure Analysis
- **Vulnerable Pattern:** Unhandled exception traceback dumps exposing local file paths, database filenames, and mock secret keys.
- **Observed Behavior:** Attackers glean architectural and directory tree details from raw 500 error screens.
- **Defense Implemented:** Production error handling with custom 403, 404, and 500 templates, coupled with internal server-side logging.

---

## 4. Final Recommendation
CYBERTRACE demonstrates that modern web security is achieved not through client-side obscurity, but through defense-in-depth: combining parameterized data access, automated output encoding, server-side authorization gates, and robust session management.
