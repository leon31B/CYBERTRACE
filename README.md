# CYBERTRACE — Digital Investigation & Threat Analysis Portal

> **A Fictional, Localhost-Only Cybersecurity Teaching Laboratory & Case Management System for College Demonstrations**

---

## 1. Project Introduction & Origin

**CYBERTRACE** is an educational cyber-range and security demonstration platform designed specifically for college projects, viva examinations, and classroom threat analysis labs. It was created from the need to demonstrate how web vulnerabilities occur at the code level, how attackers exploit them, and how developers systematically mitigate them using industry-standard defenses.

The portal combines two integrated experiences:
1. **SOC Digital Forensics Case Management Portal:** A realistic Security Operations Center portal managing incident dossiers, forensic evidence chains of custody, investigation notes, and investigator directories.
2. **Interactive Web Security Assessment Laboratory:** A hands-on testbed featuring side-by-side **Before vs. After** demonstrations of 5 critical OWASP web application vulnerabilities (SQL Injection, Cross-Site Scripting, Cross-Site Request Forgery, Broken Access Control, and Sensitive Information Disclosure).

### Project Themes & Why CYBERTRACE Was Chosen
When designing a college cybersecurity demonstration project, several common real-world themes are possible:

* **🛒 E-Commerce Security Lab:** Shopping portal focusing on search SQLi, product review stored XSS, and order ID tampering.
* **🎓 College Student Portal ("SecureCampus"):** Student grade lookup SQLi, announcement board XSS, and student-to-admin privilege escalation.
* **🏦 Mini Banking Application:** Account search SQLi, fund transfer CSRF, and account statement IDOR.
* **🏥 Patient Management System:** Patient record SQLi, doctor note stored XSS, and medical log access control.
* **🛡️ CYBERTRACE (Chosen Theme — Digital Investigation & Threat Analysis Portal):**
  * **Why this is the best college project:** A Security Operations Center / Digital Investigation portal naturally aligns with cybersecurity coursework, external examiner expectations, and threat modeling frameworks. It allows seamless integration of forensic evidence workflows, audit trails, and role-based access control alongside controlled vulnerability testing sandboxes.

---

## 2. Ethical Scope & Safe Localhost Boundaries

> [!IMPORTANT]
> **Strict Educational Boundary & Ethical Notice:**
> - CYBERTRACE is designed **strictly for educational demonstration in a localhost environment (`127.0.0.1`)**.
> - All vulnerability demonstrations are isolated in controlled local sandboxes and execute exclusively against the local SQLite database created by this project.
> - The application does **NOT** connect to external networks, remote servers, or third-party targets.
> - It contains **no** credential theft tools, malware, keyloggers, automated attack scripts, persistence mechanisms, or data exfiltration routines.
> - Vulnerability testing techniques demonstrated here must **never** be executed against systems without prior explicit, written authorization.

---

## 3. Technology Stack & Design Principles

* **Backend Framework:** Python 3 + Flask (lightweight, standard library-friendly, readable routes).
* **Database Engine:** SQLite3 (`cybertrace.db`) accessed via Python's native `sqlite3` driver with foreign key constraints.
* **Password Hashing:** Werkzeug security utilities (salted PBKDF2/scrypt hashes).
* **Template Engine:** Jinja2 (HTML5 semantic layouts, auto-escaping defenses, template inheritance).
* **Styling (CSS):** Vanilla CSS3 (custom SOC / Dark Theme with cyber cyan `#00ffcc`, amber `#ffaa00`, and critical red `#ff3366` accents; responsive grid layout).
* **Client-side Logic:** Vanilla JavaScript (no external frameworks, zero CDNs, fully offline-functional).
* **Testing:** Custom automated test suite (`test_cybertrace.py`) with 38 assertions validating authentication, RBAC, and all 5 security labs.
* **Zero Complex Tooling:** No virtual environment required, no Docker, no Node.js, no React, and no cloud dependencies.

---

## 4. System Architecture & Directory Structure

```text
cybertrace/
│
├── app.py                             # Core Flask application, controllers, RBAC decorators & lab routes
├── database.py                        # SQLite connection helpers, schema definitions & audit logging
├── requirements.txt                   # Minimal dependencies (Flask, Werkzeug)
├── setup_database.py                  # Database initializer & fictional seed data
├── cybertrace.db                      # Local SQLite database file (created on initialization)
├── test_cybertrace.py                 # Comprehensive automated test suite (38 assertions)
├── README.md                          # Master documentation, architecture, STRIDE model & viva guide
├── CYBERTRACE_ChatGPT_Conversation.md # Conversation transcript & project theme reference
│
├── static/
│   ├── css/
│   │   └── style.css                  # SOC Dark Theme design system, variables & layout
│   └── js/
│       └── app.js                     # Interactive payload helpers, tab switchers & modal handlers
│
├── templates/
│   ├── base.html                      # Master layout with sidebar navigation & top telemetry bar
│   ├── login.html                     # Authentication portal with demo credential quick-reference
│   ├── dashboard.html                 # Main SOC operations & telemetry dashboard
│   ├── cases.html                     # Incident dossiers & case search
│   ├── case_detail.html               # Case brief, evidence locker & investigation notes
│   ├── evidence.html                  # Evidence chain-of-custody catalog
│   ├── investigators.html             # Security personnel directory
│   ├── profile.html                   # Operator profile & CSRF update form
│   ├── database_viewer.html           # Classroom database inspector with masked passwords (Admin only)
│   │
│   ├── security/
│   │   ├── index.html                 # Security assessment findings summary & lab catalog
│   │   ├── attack_surface.html        # Attack Surface Analysis & visual boundary map
│   │   ├── threat_model.html          # STRIDE matrix & threat-flow diagram
│   │   ├── sqli.html                  # SQL Injection lab (Vulnerable vs Parameterized query)
│   │   ├── xss.html                   # XSS lab (Reflected & Stored demos: Raw DOM vs Auto-Escaped)
│   │   ├── csrf.html                  # CSRF lab (Vulnerable POST vs Synchronizer Token pattern)
│   │   ├── access_control.html        # Broken Access Control lab (Missing RBAC vs @role_required)
│   │   └── information_disclosure.html # Verbose stack trace leak vs Sanitized error handling
│   │
│   ├── admin/
│   │   ├── dashboard.html             # Admin overview & system health
│   │   ├── users.html                 # User account clearance manager
│   │   ├── cases.html                 # Admin case manager & registration
│   │   └── evidence.html              # Administrative chain-of-custody archive
│   │
│   └── errors/
│       ├── 403.html                   # Access Denied / Insufficient Clearance template
│       ├── 404.html                   # Resource or Dossier Not Found template
│       └── 500.html                   # Internal Server Error (Sanitized, debug-safe) template
│
└── docs/
    ├── attack_surface.md              # Detailed Attack Surface documentation
    ├── threat_model.md                # STRIDE Threat Model documentation
    └── security_assessment.md         # College security assessment report
```

---

## 5. Relational Database Schema & Data Models

The SQLite database (`cybertrace.db`) contains six relational tables:

1. **`users`**: Operator authentication records with hashed passwords, roles (`ADMIN`, `INVESTIGATOR`, `ANALYST`), and department assignments.
2. **`cases`**: Incident dossiers tracking severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), status (`OPEN`, `INVESTIGATING`, `CLOSED`), and assigned lead.
3. **`evidence`**: Forensic artifacts (disk images, packet captures, memory dumps) linked to cases with unique evidence codes.
4. **`investigation_notes`**: Chronological observation logs added to cases by authorized investigators.
5. **`audit_logs`**: Immutable security event trail recording operator ID, action performed, IP address, and timestamp.
6. **`demo_sqli_records`**: Isolated sandbox table used strictly for the SQL Injection demonstration to protect application data.

---

## 6. Demonstration Accounts (Demo Credentials)

| Role | Username | Password | Access Clearance & Purpose in Demonstration |
| :--- | :--- | :--- | :--- |
| **ADMIN** | `admin` | `admin123` | **Full Clearance:** User management, case creation, system audit logs, and raw database viewer (`/database`). |
| **INVESTIGATOR** | `investigator` | `investigator123` | **Operational Clearance:** Open new cases, log evidence, append investigation notes, test security labs. |
| **ANALYST** | `analyst` | `analyst123` | **Read-Only Clearance:** Search cases, view logs, test HTTP 403 Broken Access Control denial. |

*Note: All passwords are saved in `cybertrace.db` using salted cryptographic password hashes (PBKDF2/scrypt).*

---

## 7. How to Install and Run (Beginner-Friendly)

### Step 1: Open Terminal or Command Prompt
Navigate to the project folder:
```bash
cd "c:\Users\MOHIT\Desktop\sakshi di project"
```

### Step 2: Verify Python
Ensure Python 3.9 or higher is installed:
```bash
python --version
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Initialize / Reset Database
```bash
python setup_database.py
```
*This creates `cybertrace.db` and populates realistic fictional cases, evidence, notes, and user accounts.*

### Step 5: Start the Application
```bash
python app.py
```

### Step 6: Open in Web Browser
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 8. Interactive Security Labs: Vulnerabilities & Mitigations

Each security lab is designed as **one lab with two modes (Vulnerable Demo vs Secure Mitigation)**:

| # | Vulnerability | Vulnerable Implementation | Attack Payload | Secure Mitigation |
|---|---------------|---------------------------|----------------|-------------------|
| **1** | **SQL Injection (SQLi)** | String formatting into raw SQL: `f"SELECT ... WHERE code = '{input}'"` | `' OR '1'='1` | Parameterized SQL queries using `?` placeholders; driver treats input purely as literal data. |
| **2** | **Cross-Site Scripting (XSS)** | Disabling Jinja2 auto-escaping using the `\|safe` filter in templates | `<b>CYBERTRACE TEST</b>` | Contextual HTML entity escaping (`{{ payload }}` without `\|safe`); converts `<` to `&lt;`. |
| **3** | **CSRF** | POST endpoint executes state changes relying solely on session cookie | Cross-origin form submission changing profile data | Synchronizer CSRF Token Pattern; validates `session['csrf_token']` on every state-changing POST. |
| **4** | **Broken Access Control (BAC)** | Relying on UI link hiding; endpoint has no server-side role check | Analyst directly visits `/admin/*` or `/demo/access_control/protected_admin_file` | Server-side `@role_required(['ADMIN'])` decorator that validates session role and aborts with HTTP 403 Forbidden. |
| **5** | **Sensitive Information Disclosure** | Verbose error handling and `debug=True` leaking call stack and keys | Triggering unhandled exception via invalid parameters | Sanitized generic HTTP 500 error page (`debug=False`), internal server-side logging, and password hash masking. |

---

## 9. Attack Surface Analysis

The project identifies and documents five distinct attack surface tiers:

1. **Authentication & Session Boundary:**
   - Entry point: `/login`, `/logout`.
   - Threat: Brute-force guessing, credential stuffing, session fixation.
   - Defense: Salted password hashing, session regeneration, rate-aware logging.
2. **User Input & Data Entry Surface:**
   - Entry point: Case search query (`/cases?q=`), Case notes submission (`/cases/<id>/notes`), Evidence logging.
   - Threat: SQL Injection, Stored & Reflected XSS.
   - Defense: Parameterized SQL statements, Jinja2 auto-escaping, strict input type validation.
3. **State-Changing Actions Surface:**
   - Entry point: Operator profile updates (`/profile`), User role updates (`/admin/users/update`).
   - Threat: Cross-Site Request Forgery (CSRF).
   - Defense: Cryptographic synchronizer anti-CSRF tokens validated server-side.
4. **Authorization & URL Routing Surface:**
   - Entry point: Administrative portals (`/admin/*`), Raw database viewer (`/database`).
   - Threat: Forced browsing, privilege escalation (Broken Access Control / IDOR).
   - Defense: Route-level RBAC decorators (`@role_required`) intercepting unauthorized requests.
5. **Error & Exception Handling Surface:**
   - Entry point: Unhandled backend exceptions, invalid parameter types.
   - Threat: Internal directory disclosure, database driver leaks, configuration exposure.
   - Defense: Custom 403, 404, and 500 handlers serving sanitized user-friendly templates.

---

## 10. STRIDE Threat Modeling Breakdown

The CYBERTRACE architecture is analyzed using the **STRIDE** threat model:

| Threat Category | Potential Attack Vector in CYBERTRACE | Architectural Defense / Mitigation |
| :--- | :--- | :--- |
| **S — Spoofing** | Adversary attempts to log in as `admin` by guessing credentials or forging session cookies. | Salted PBKDF2/scrypt password hashing with `werkzeug.security`; cryptographically signed HTTP cookies. |
| **T — Tampering** | Manipulating case records or injecting SQL commands via search parameters. | Parameterized SQL queries (`?` placeholders) and strict server-side input validation. |
| **R — Repudiation** | An operator deletes evidence or modifies records and denies having performed the action. | Centralized immutable `audit_logs` table recording timestamp, operator ID, action performed, and client IP. |
| **I — Information Disclosure** | Triggering an unhandled exception to read internal file paths or reading password hashes in the database viewer. | Custom sanitized 500 error pages, `debug=False` configuration, and explicit password masking (`[HASHED-PBKDF2/SCRYPT]`). |
| **D — Denial of Service** | Exhausting SQLite database locks or crashing the Python process with malicious payloads. | Scoped request transactions, connection closing helpers, and isolated sandbox tables for SQLi testing. |
| **E — Elevation of Privilege** | An `ANALYST` accessing administrative routes (`/database`, `/admin/users`) via direct URL manipulation. | Server-side `@role_required(['ADMIN'])` authorization decorator returning HTTP 403 Forbidden. |

---

## 11. Comprehensive Viva Examination & Pitching Guide

### Part 1: Your Project in One Sentence
> *"CYBERTRACE is an educational digital forensics and web application security platform that demonstrates Attack Surface Analysis, STRIDE Threat Modeling, and Role-Based Access Control in Flask, featuring interactive side-by-side demonstrations of 5 critical OWASP vulnerabilities and their secure mitigations."*

---

### Part 2: 5-Minute Timed Pitch Breakdown

* **0:00 – 0:30 (Opening & Purpose):**
  * State the project title and objective: To teach and demonstrate how common web application vulnerabilities happen at the code level and how to systematically fix them using defense-in-depth principles.
* **0:30 – 1:30 (Architecture & Role-Based Access Control):**
  * Explain the stack: Python, Flask, SQLite, and Vanilla CSS/JS.
  * Show the three operator roles: **Admin**, **Investigator**, and **Analyst**.
  * Log in as `investigator` and highlight the SOC dashboard, active incident dossiers, and evidence locker.
* **1:30 – 3:30 (Live Demonstration of the Security Labs):**
  * **SQL Injection:** Enter `' OR '1'='1`. In Vulnerable Mode, show how string concatenation returns all records. In Secure Mode, show how parameterized queries treat the string as literal data.
  * **XSS:** Enter `<b>CYBERTRACE TEST</b>`. Show how unescaped Jinja2 `|safe` injects DOM elements, while auto-escaping converts tags to safe HTML entities.
  * **CSRF:** Demonstrate an unauthorized POST without a token, then show the secure form rejecting requests without a valid synchronizer token.
  * **Broken Access Control:** As an `analyst`, attempt to access `/database` or `/admin/users`. Show the server-side `@role_required` decorator intercepting the request and returning an HTTP 403 Forbidden page.
  * **Information Disclosure:** Show the sanitized 500 error page that prevents stack trace leaks.
* **3:30 – 4:30 (Defense-in-Depth & Database Inspection):**
  * Log in as `admin`. Open the **Database Viewer** (`/database`).
  * Point out to the examiner that passwords are never stored in plain text and are masked as `[HASHED-PBKDF2/SCRYPT]`.
  * Show the live `audit_logs` table tracking every test action taken during the demo.
* **4:30 – 5:00 (Conclusion & Testing Verification):**
  * Conclude by mentioning the automated test suite: 38/38 unit and integration tests passing with 100% success rate.

---

### Part 3: Top 10 High-Scoring Viva Questions & Full Examiner-Ready Answers

#### 1. What problem does CYBERTRACE solve?

**Answer:**
> “CYBERTRACE addresses the problem of securing a web-based digital investigation system that contains sensitive information such as cases, evidence, investigator notes, and user information.
>
> We created a fictional investigation portal and combined it with a security assessment laboratory. This allows us to demonstrate common web vulnerabilities and their mitigations in the same application.
>
> The project specifically demonstrates SQL Injection, Cross-Site Scripting (XSS), CSRF, Broken Access Control, and Sensitive Information Disclosure. The normal application uses the corresponding security controls, while the vulnerable implementations are isolated for educational purposes.”

**If examiner asks: “Why did you choose this problem?”**
> “Because a digital investigation system naturally contains sensitive data and different user roles, so it provides a realistic context for demonstrating authentication, authorization, and web application security.”

---

#### 2. Explain your project architecture.

**Answer:**
> “CYBERTRACE follows a simple Flask-based web architecture.
>
> The user interacts with the application through a browser. Requests are received by the Flask application. Flask handles authentication, authorization, application routes, and the security laboratory. Jinja2 is used for dynamic HTML rendering.
>
> The application then communicates with the SQLite database through our database layer.
>
> The main flow is:
>
> **Browser → Flask → Authentication/RBAC → Application or Security Lab → SQLite Database → Response.**
>
> The normal application contains users, cases, evidence, investigation notes, and audit logs. The SQL Injection demonstration has a separate `demo_sqli_records` table so the vulnerable demonstration does not interact with the real application data.”

```text
              USER
                │
                ▼
         WEB BROWSER
                │
                ▼
        ┌───────────────┐
        │ Flask / Jinja │
        └───────┬───────┘
                │
        Authentication
             + RBAC
                │
        ┌───────┴────────┐
        │                │
        ▼                ▼
 Normal Application   Security Labs
        │                │
        └───────┬────────┘
                ▼
        SQLite Database
                │
      ┌─────────┼─────────┐
      ▼         ▼         ▼
    Users     Cases    Evidence
                 │
              Notes
                 │
            Audit Logs
```

---

#### 3. Why did you choose Flask and SQLite?

**Why Flask?**
> “We chose Flask because it is a lightweight Python web framework that gives us direct control over routes, authentication, sessions, and request handling. For a project of this size, we didn't need a large, heavy framework.”

**Why SQLite?**
> “We chose SQLite because the project is designed for localhost and educational use. SQLite is a lightweight relational database that doesn't require a separate database server process.”

**If examiner asks: “Why not Django?”**
> “Django is also suitable, but Flask gives us a simpler, cleaner architecture and makes it easier for us to demonstrate the underlying security concepts directly without framework middleware obscuring the mechanics.”

**If examiner asks: “Why not MySQL?”**
> “MySQL would also work, but SQLite was sufficient for our local educational scope and reduced external dependency and setup requirements.”

---

#### 4. Explain SQL Injection and how you prevented it.

**Answer:**
> “SQL Injection occurs when user-controlled input is incorporated into an SQL query in an unsafe way, allowing the input to affect the SQL query syntax itself.
>
> In our vulnerable demonstration, we intentionally concatenate the input into the SQL query:
>
> `SELECT ... WHERE record_id = 'user_input'`
>
> We demonstrate this using the payload:
>
> `' OR '1'='1`
>
> This changes the Boolean logic of the vulnerable query and causes all demonstration records to be returned.
>
> In the secure implementation, we use a parameterized query with placeholders (`?`). The input is passed separately from the SQL statement, so the database driver treats it strictly as literal data rather than executable SQL code.”

**If examiner asks: “How did you test it?”**
> “We entered `' OR '1'='1` into the vulnerable mode and it returned all sandbox records. The same input in secure mode returned zero records because no record had a literal ID of `' OR '1'='1`.”

---

#### 5. Why is your SQL Injection code intentionally vulnerable?

**Answer:**
> “Because CYBERTRACE is also a security assessment laboratory. The purpose of the vulnerable implementation is educational—we want to show exactly why unsafe SQL construction is dangerous and then compare it directly with the secure implementation.
>
> The vulnerable code is isolated from the normal application database. It only operates against the dedicated `demo_sqli_records` table.”

**If examiner asks: “Would you keep vulnerable code in a real production application?”**
> “No. The vulnerable code exists only for the controlled educational demonstration. A production application should strictly use the secure parameterized implementation.”

**If examiner asks: “Can your SQLi demo access the users table?”**
> “No. The demonstration is isolated to the SQLi sandbox and does not expose the application's users, cases, evidence, or audit-log tables.”

---

#### 6. Explain the difference between authentication and authorization.

> **“Authentication answers: Who are you? Authorization answers: What are you allowed to access or do?”**

**Detailed Explanation:**
> “In CYBERTRACE, authentication occurs when the user logs in with valid credentials at `/login`.
>
> After authentication, authorization determines what that user can access based on their role:
> - **ADMIN** (full system clearance, user management, `/database` viewer)
> - **INVESTIGATOR** (case creation, evidence logging, investigation notes)
> - **ANALYST** (read-only case exploration, security lab testing)
>
> For example, an Analyst can access normal investigation views but cannot access the Admin dashboard or database viewer. The server intercepts unauthorized requests and returns an HTTP 403 Forbidden screen.”

```text
Authentication: "Are you Marcus Vance?"
Authorization:  "Are you allowed to open the Admin Database Viewer?"
```

---

#### 7. How does your RBAC work?

**Answer:**
> “CYBERTRACE uses role-based access control. Each authenticated user has a role stored in the session: `ADMIN`, `INVESTIGATOR`, or `ANALYST`.
>
> Before accessing a protected route, the backend checks the user's role using a custom Python decorator:
>
> `@role_required(['ADMIN'])`
>
> If the user's role is not in the allowed list, the application aborts and returns an HTTP 403 Forbidden response.”

**If examiner asks: “Why not just hide the Admin button in the HTML?”**
> “Because frontend restrictions can easily be bypassed. A user can directly type the restricted URL (like `/database` or `/admin/users`) into their browser. Therefore, authorization must always be strictly enforced on the server-side backend.”

---

#### 8. Explain XSS and how Jinja2 helps prevent it.

**Answer:**
> “XSS stands for Cross-Site Scripting. It occurs when untrusted input is rendered by the browser as HTML or script instead of being safely treated as text.
>
> In our vulnerable XSS demonstration, we intentionally use Jinja2's `|safe` filter, which disables automatic HTML entity encoding and allows user-supplied HTML to be rendered into the DOM.
>
> For example:
>
> `<b>CYBERTRACE TEST</b>`
>
> is rendered as bold formatted text in the vulnerable panel.
>
> In the secure implementation, we use standard Jinja2 rendering:
>
> `{{ payload }}`
>
> Jinja2 automatically escapes special HTML characters (converting `<` to `&lt;` and `>` to `&gt;`), so the browser treats the input strictly as inert text rather than interpreting it as executable HTML.”

**If examiner asks: “Why is `|safe` dangerous?”**
> “Because it explicitly disables Jinja2's auto-escaping mechanism. If the data is user-controlled, malicious HTML or JavaScript content could be executed by the victim's browser.”

**If examiner asks: “What is your XSS payload?”**
> “We use harmless formatting markup such as `<b>CYBERTRACE TEST</b>` for demonstration. In accordance with safety principles, we do not implement cookie theft, credential harvesting, or external callbacks.”

---

#### 9. Explain CSRF and how your token works.

**Answer:**
> “CSRF stands for Cross-Site Request Forgery. It occurs when an attacker tricks an authenticated user's browser into making an unwanted state-changing request to a target website where they are logged in.
>
> In our vulnerable demonstration, the endpoint accepts state-changing POST requests relying solely on the browser's automatic cookie transmission, without validating request origin.
>
> In the secure implementation, the application generates a unique, cryptographically random CSRF token stored in `session['csrf_token']`. This token is embedded as a hidden field in the form. When submitted, the server compares the form's token with the session token.
>
> If the token is missing or does not match, the request is immediately rejected. If it matches, the operation proceeds.”

**If examiner asks: “Is CSRF the same as XSS?”**
> “No. XSS is about injecting untrusted script into a web page to execute in a user's browser. CSRF is about tricking an authenticated user's browser into performing an unauthorized action on another site without their knowledge.”

**If examiner asks: “Why does CSRF work in the first place?”**
> “Because web browsers automatically attach session cookies to outgoing HTTP requests to the target domain, even when the request originates from a different third-party website.”

---

#### 10. What would you change if this became a production application?

**Answer:**
> “CYBERTRACE is intentionally designed as a localhost educational cyber-range and teaching laboratory, so it is not intended for direct production deployment.
>
> If we converted it into an enterprise production system, we would implement:
> 1. **Production WSGI Server:** Replace Flask's built-in development server with Gunicorn or Waitress behind an NGINX reverse proxy.
> 2. **Transport Layer Security (HTTPS/TLS):** Enforce TLS 1.3 with automated certificate renewal to protect session cookies in transit.
> 3. **HTTP Security Headers:** Configure Content Security Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options (DENY), and X-Content-Type-Options (nosniff).
> 4. **Enhanced Session Management:** Add absolute session timeouts, idle timeouts, and the `__Host-` cookie prefix with `Secure`, `HttpOnly`, and `SameSite=Strict`.
> 5. **Secret Management:** Store session keys and environment variables in a dedicated secrets manager rather than local config files.
> 6. **Production Database:** Migrate from SQLite to PostgreSQL with read replicas and automated backups for high concurrency.
> 7. **Monitoring & WAF:** Deploy a Web Application Firewall (WAF) and centralize audit logs into a SIEM (Security Information and Event Management) system.”

**If examiner asks: “So is your current application 100% secure?”**
> “No system is 100% secure because security is a continuous risk-mitigation process, not a final destination. CYBERTRACE implements robust defenses for the targeted OWASP Top 10 vulnerabilities in its scope, while keeping the vulnerable demonstration sandboxes strictly isolated.”

---

## 12. Automated Verification & Test Results

Run the built-in test suite to verify all system components:
```bash
python test_cybertrace.py
```

### Verified Test Matrix (38/38 Passed)

```text
=================================================================
 CYBERTRACE Comprehensive Automated Verification Suite
=================================================================
 [PASS] Unauthenticated access to /dashboard redirects to /login
 [PASS] Unauthenticated access to /cases redirects to /login
 [PASS] Failed login rejects wrong password with flash message
 [PASS] Failed login rejects non-existent user
 [PASS] Analyst login succeeds with valid credentials
 [PASS] Analyst blocked from /database with HTTP 403
 [PASS] Analyst blocked from /admin/dashboard with HTTP 403
 [PASS] Analyst blocked from /admin/users with HTTP 403
 [PASS] Analyst blocked from creating new cases with HTTP 403
 [PASS] Analyst blocked from adding evidence with HTTP 403
 [PASS] Cases catalog renders HTTP 200
 [PASS] Case dossier /cases/1 renders HTTP 200 with evidence and notes
 [PASS] Evidence locker renders HTTP 200
 [PASS] Investigators directory renders HTTP 200
 [PASS] Operator profile page renders HTTP 200
 [PASS] Security assessment dashboard renders HTTP 200
 [PASS] Attack Surface page renders HTTP 200 with visual boundary map
 [PASS] Threat Model page renders HTTP 200 with STRIDE matrix
 [PASS] SQLi vulnerable mode executes string concatenation and returns sandbox records
 [PASS] SQLi secure mode parameterizes input and neutralizes attack
 [PASS] XSS lab renders both unescaped markup and safe auto-escaped HTML entity
 [PASS] CSRF lab renders HTTP 200
 [PASS] Vulnerable CSRF endpoint accepts request without token
 [PASS] Secure CSRF endpoint rejects request missing token
 [PASS] Secure CSRF endpoint accepts request with valid token
 [PASS] Unprotected admin file allows low-privileged analyst access
 [PASS] Protected admin file rejects analyst with HTTP 403 Forbidden
 [PASS] Information Disclosure lab renders HTTP 200
 [PASS] Simulated leak endpoint demonstrates verbose traceback with fictional DEMO keys
 [PASS] Investigator is authorized to access /cases/new (HTTP 200)
 [PASS] Investigator is authorized to access /evidence/new (HTTP 200)
 [PASS] Admin accesses /database successfully (HTTP 200)
 [PASS] Database viewer strictly masks passwords as [HASHED-PBKDF2/SCRYPT]
 [PASS] Admin accesses /admin/dashboard successfully (HTTP 200)
 [PASS] Admin accesses /admin/users successfully (HTTP 200)
 [PASS] Admin accesses protected admin file with HTTP 200 and JSON payload
 [PASS] Custom 404 Not Found error template renders
 [PASS] Audit logs successfully record system actions in SQLite
=================================================================
 FINAL TEST RESULT: 38/38 ASSERTIONS PASSED (100%)
=================================================================
```

---

## 13. Troubleshooting & Frequently Asked Questions

* **Port 5000 is occupied:**
  If port 5000 is used by another service, start the application on port 5001:
  ```bash
  python -c "import app; app.app.run(port=5001, debug=False)"
  ```
* **Database Reset:**
  To reset the database back to clean initial demo data:
  ```bash
  python setup_database.py
  ```
* **CSS Changes Not Updating:**
  Perform a hard refresh (`Ctrl + F5` on Windows) to clear the browser cache.
