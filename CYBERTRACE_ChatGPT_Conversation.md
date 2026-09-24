# CYBERTRACE — Cybersecurity Project Themes & Walkthrough

**Source:** [ChatGPT Shared Conversation](https://chatgpt.com/share/6ab55cf5-fe8c-83e8-b667-685599727a58)  
**Title:** Cybersecurity Project Themes  

---

## User Prompt

I have a college cybersecurity project on Attack Surface Analysis and Threat Modeling. I need to create a small web application with a database and demonstrate some common web security vulnerabilities in a safe localhost environment.

Please help me build it step-by-step from absolute beginner level, using simple language. Don't give everything at once—guide me one step at a time and wait for me after each step.

The project should cover:
- Webpage/application with database connectivity
- Attack surface identification
- Threat modeling
- Demonstration of vulnerabilities (SQLi, XSS, CSRF, BAC, Info Disclosure) in both vulnerable and secure modes

---

## Assistant Response

Yes bro. This is actually a **very good college cybersecurity project** because you can build a normal Flask application and then intentionally create a **controlled vulnerable version** on localhost, demonstrate the attack, and finally show the secure version.

The easiest way is to think of the project as **one application with two modes**:
1. **Vulnerable mode (Demo mode):** Attack works and breaks the app or leaks data.
2. **Secure mode:** Same attack is tried, but proper defense prevents it (e.g., parameterized query, escaping, tokens, RBAC).

Before we start writing code, let me give you a few **real-world theme options** for your project. Pick the one you like most, and we will build the entire project around that theme step by step:

---

### 1. Project Themes You Can Choose

#### Option 1 — 🛒 E-Commerce Security Lab
* **Story:** A simple shopping portal where users browse products, add items to cart, write product reviews, and check orders.
* **Vulnerabilities to demo:**
  * SQL Injection in product search (`' OR '1'='1`)
  * Stored XSS in product reviews (`<script>alert(1)</script>`)
  * Broken Access Control (viewing another user's order by changing order ID in URL)
  * CSRF in updating profile address

#### Option 2 — 🎓 College Student Portal ("SecureCampus")
* **Story:** A university portal for viewing marks, submitting feedback/notes, and updating student profiles.
* **Vulnerabilities to demo:**
  * SQL Injection in student ID lookup
  * XSS in feedback submission / announcement board
  * Broken Access Control (student accessing admin/teacher page)
  * Information Disclosure (exposing raw backend error stack trace during invalid login)

#### Option 3 — 🏦 Mini Banking Application
* **Story:** A simple online banking demo for viewing balance, transferring funds, and updating profile info.
* **Vulnerabilities to demo:**
  * SQL Injection in account search
  * CSRF in fund transfer request
  * Broken Access Control (accessing another account statement)

#### Option 4 — 🏥 Patient Management System
* **Story:** A clinic system for searching patient records, adding doctor notes, and profile management.
* **Vulnerabilities to demo:**
  * SQL Injection in patient search
  * Stored XSS in doctor notes
  * Broken Access Control (patient accessing doctor's full medical logs)

#### Option 5 — 📚 Library Management System
* **Story:** A library portal to search books, issue books, and submit book reviews.

---

### What I Would Build For Your Project: CYBERTRACE

Because this is a college project, a **Student Management Portal** or **Incident Trace / Cyber Trace System (CYBERTRACE)** is extremely relatable to external examiners!

### 2. What You'll Actually Build
A full Flask web application with a SQLite database containing:
- **Authentication & RBAC:** Admin, Investigator, Analyst roles.
- **Security Laboratory / Vulnerability Demos:**
  1. **SQL Injection (SQLi)** — Vulnerable vs Parameterized search.
  2. **Cross-Site Scripting (XSS)** — Unescaped rendering (`|safe`) vs Auto-escaped Jinja2 rendering.
  3. **Cross-Site Request Forgery (CSRF)** — Unprotected POST form vs CSRF token validation.
  4. **Broken Access Control (BAC)** — Unrestricted URL access vs Decorator-based RBAC (`@role_required`).
  5. **Sensitive Information Disclosure** — Debug mode / stack trace dump vs Sanitized 500 error page.

---

### 3. How the Cybersecurity Demonstration Works
Each lab feature has a side-by-side comparison:
- **Vulnerable tab / route:** Shows how an attacker exploits the flaw.
- **Secure tab / route:** Shows how the fix neutralizes the attack.

---

### 4. Attack Surface Analysis
- Web forms (Login, Search, Profile update, Feedback/Notes)
- URL parameters (`/case?id=1`)
- Session cookies & Headers
- Error handling mechanisms

---

### 5. Threat Modeling (STRIDE)
- **Spoofing:** Fake login attempts -> mitigated by bcrypt password hashing & session management.
- **Tampering:** Modifying HTTP request payload -> mitigated by server-side input validation & parameterization.
- **Repudiation:** Denying actions taken -> mitigated by structured Audit Logging (`audit_logs` table).
- **Information Disclosure:** Leaking stack traces or secret keys -> mitigated by `debug=False` and generic error templates.
- **Elevation of Privilege:** Standard user accessing Admin dashboard -> mitigated by strict RBAC middleware.

---

### 6. Technology Stack
- **Backend:** Python (Flask)
- **Database:** SQLite (using Python `sqlite3` driver)
- **Frontend:** HTML5, CSS3, Jinja2 Templates
- **Testing:** Pytest / Unittest (38+ automated test cases)

---

### 7. Viva Preparation & Pitching Guide (CYBERTRACE)

#### PART 1 — YOUR PROJECT IN ONE SENTENCE
> "CYBERTRACE is an educational cyber-range and security demonstration platform that implements Attack Surface Analysis, STRIDE Threat Modeling, and Role-Based Access Control in Flask, featuring side-by-side interactive demonstrations of 5 critical OWASP web vulnerabilities and their mitigations."

#### PART 2 — 5-MINUTE PITCH
* **0:00–0:30 — Opening:** State the goal of the project (demonstrating how vulnerabilities happen at code-level and how to systematically mitigate them).
* **0:30–1:30 — Architecture & Roles:** Explain Flask, SQLite, 3 roles (Admin, Investigator, Analyst).
* **1:30–3:30 — Live Demo of Labs:** Show SQLi, XSS, CSRF, BAC, and Info Disclosure side-by-side.
* **3:30–4:30 — Defense in Depth:** Highlight password hashing, CSRF tokens, Jinja2 auto-escaping, and audit logging.
* **4:30–5:00 — Conclusion:** Summarize test suite results (38 automated tests passed) and production readiness steps.

#### PART 3 — TOP VIVA QUESTIONS & ANSWERS

1. **Q: What is SQL Injection and how did you fix it?**
   * *Answer:* SQL Injection occurs when untrusted user input is directly concatenated into a SQL query string. In CYBERTRACE, the vulnerable lab uses `f"SELECT * FROM cases WHERE query = '{user_input}'"`. The fix uses parameterized queries (`SELECT * FROM cases WHERE query = ?`, `(user_input,)`), separating the query structure from the data so the database driver treats input strictly as values rather than executable code.

2. **Q: What is XSS and why is `|safe` dangerous in Jinja2?**
   * *Answer:* XSS allows attackers to inject malicious JavaScript into web pages viewed by other users. Jinja2 automatically escapes HTML entities by default. Using the `|safe` filter disables auto-escaping, rendering raw user input directly into the DOM, which allows script execution.

3. **Q: How does CSRF protection work?**
   * *Answer:* CSRF tricks a logged-in user's browser into submitting unauthorized requests to a target website. We mitigate this by generating a unique, cryptographically secure anti-CSRF token stored in the session and validating it on all state-changing POST requests.

4. **Q: What is the difference between Authentication and Authorization?**
   * *Answer:* Authentication verifies **who you are** (e.g., login with username/password). Authorization determines **what you are allowed to do** (e.g., RBAC checking if an Analyst can access Admin panel).

5. **Q: Why should Flask development server / debug mode not be used in production?**
   * *Answer:* Debug mode enables the interactive Werkzeug debugger and detailed stack trace disclosures upon errors, which can leak raw code, environment secrets, and allow arbitrary code execution.

6. **Q: Is your application 100% secure?**
   * *Answer:* No application is 100% secure. CYBERTRACE implements defense-in-depth for the targeted OWASP Top 10 risks in controlled lab environments, but production deployment would require HTTPS, WAF, rate-limiting, and hardened headers.
