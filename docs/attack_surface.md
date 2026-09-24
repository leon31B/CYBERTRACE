# Attack Surface Analysis Documentation — CYBERTRACE

## 1. Executive Summary
This document provides an educational Attack Surface Analysis for the **CYBERTRACE Digital Investigation & Threat Analysis Portal**. The objective is to identify all entry points, network boundaries, and data conduits through which an adversary or unauthorized operator could attempt to manipulate application state, escalate privileges, or access restricted forensic intelligence.

---

## 2. Attack Surface Categorization

### 2.1 Web Form & User Input Layer
| Component / Route | Vector | Threat Identified | Defensive Countermeasure |
| :--- | :--- | :--- | :--- |
| `POST /login` | Form parameters: `username`, `password` | SQL injection in authentication check; credential brute forcing | SQLite parameterized queries (`?`), PBKDF2/scrypt password hashing with salt |
| `GET /cases?q=` | URL query string parameter `q` | SQL injection via wildcard search manipulation | Parameterized query with bound parameters (`c.title LIKE ?`) |
| `POST /cases/<id>/add_note` | Multiline text `note` | Stored Cross-Site Scripting (XSS) in forensic review view | Jinja2 contextual HTML entity escaping upon render |
| `POST /profile` | Form parameters: `full_name`, `email`, `department` | Cross-Site Request Forgery (CSRF) state tampering | Cryptographic synchronizer CSRF token validation |
| `POST /cases/new` | Multi-field case registration | Input tampering, ID spoofing | Server-side role validation (`INVESTIGATOR` or `ADMIN`) + parameterized insert |

### 2.2 Session & Authentication Layer
- **Session Cookie (`session`):** Signed with cryptographic `app.secret_key`. Prevents client-side cookie modification.
- **CSRF Token:** Cryptographically unpredictable random token generated on session creation (`session['csrf_token']`), verified on all state-changing POST operations.
- **Credential Storage:** Stored in the `users` table as irreversible PBKDF2/scrypt hashes via `werkzeug.security`. Passwords are never stored or logged in plaintext.

### 2.3 Role-Based Authorization Layer
- **Client-Side vs Server-Side:** In vulnerable architectures, administrative buttons are hidden in the browser UI, but backend routes remain accessible. CYBERTRACE enforces backend authorization using the `@role_required(['ADMIN'])` decorator.
- **Protected Paths:**
  - `/database`: Admin only
  - `/admin/*`: Admin only
  - `/cases/new`: Investigator & Admin only
  - `/evidence/new`: Investigator & Admin only

### 2.4 Diagnostic & Error Layer
- **500 Error Responses:** Generic customized error template (`500.html`) prevents exposing raw Python stack traces, internal paths, or library versions.
- **Database Viewer:** Strictly accessible only by users with the `ADMIN` role. Password column displays `[HASHED-PBKDF2/SCRYPT]` to ensure operational confidentiality during demonstrations.

---

## 3. Visual Attack Boundary Tree
```text
CYBERTRACE Application Input Boundary
│
├── [1] Authentication & Identity
│   ├── Login Form (/login) ────────────► SQL Injection & Brute Force Risk
│   ├── Session Cookie (session) ───────► Session Tampering & Hijacking
│   └── Profile Update (/profile) ──────► CSRF & Privilege Escalation
│
├── [2] Case Management Operations
│   ├── Search Bar (/cases?q=) ─────────► SQL Injection (LIKE clause)
│   ├── Investigation Notes ────────────► Stored & Reflected XSS
│   └── Evidence Registration ──────────► Arbitrary Input Injection
│
├── [3] Administrative Subsystems
│   ├── Admin Routes (/admin/*) ────────► Broken Access Control (Bypass)
│   ├── Database Viewer (/database) ────► Sensitive Data Exposure
│   └── Raw Parameters (/cases/<id>) ───► Insecure Direct Object Ref (IDOR)
│
└── [4] Diagnostic & Error Handling
    └── Unhandled Exceptions (500) ─────► Information Disclosure
```

---

## 4. Conclusion
By identifying and documenting each entry point across the application, the attack surface has been systematically reduced through server-side authorization gates, parameterization, and output encoding.
