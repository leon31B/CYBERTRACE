# Threat Model (STRIDE) Documentation — CYBERTRACE

## 1. Introduction
This Threat Model evaluates the **CYBERTRACE Digital Investigation & Web Security Assessment Lab** utilizing the **STRIDE** methodology. STRIDE categorizes cybersecurity threats based on six core security attributes.

---

## 2. STRIDE Assessment Matrix

### 2.1 [S] Spoofing (Identity Deception)
- **Threat:** An adversary attempts to impersonate an authorized investigator or administrator to view classified forensic dossiers.
- **Attack Vector:** Credential stuffing, session cookie tampering, or unauthorized user creation.
- **Impact:** Compromise of case confidentiality and chain-of-custody validity.
- **Mitigation:**
  - Secure session cookies signed by Flask with strong secret key.
  - Salted PBKDF2/scrypt password hashing preventing reverse-lookup.
  - Login form sanitization and audit logging of all authentication events.

### 2.2 [T] Tampering (Data Modification)
- **Threat:** An adversary alters evidence details, changes case severity levels, or modifies investigator notes.
- **Attack Vector:** SQL Injection (`' OR 1=1`) or Cross-Site Request Forgery (CSRF).
- **Impact:** Corrupted forensic evidence inadmissible in educational demonstrations; altered case outcomes.
- **Mitigation:**
  - 100% Parameterized queries (`cursor.execute("...", (param,))`) across all production routes.
  - Cryptographic Synchronizer CSRF tokens embedded in all state-changing POST forms.

### 2.3 [R] Repudiation (Denial of Action)
- **Threat:** An operator denies having accessed a classified file or modified an evidence status.
- **Attack Vector:** Performing operations in an unmonitored or unlogged web application.
- **Impact:** Inability to maintain forensic provenance or determine culpability for data changes.
- **Mitigation:**
  - Centralized, append-only `audit_logs` table tracking user ID, IP address, exact action string, and timestamp.
  - Non-resettable logs accessible via the Administrative Dashboard.

### 2.4 [I] Information Disclosure (Data Leakage)
- **Threat:** Internal file paths, database connection strings, or system exceptions are leaked to users.
- **Attack Vector:** Triggering HTTP 500 exceptions, stack trace errors, or viewing raw database dumps.
- **Impact:** Provides adversaries with precise architectural reconnaissance to craft targeted exploits.
- **Mitigation:**
  - Custom production error handlers (`@app.errorhandler(500)`).
  - Masked credentials in the Database Viewer (`[HASHED-PBKDF2/SCRYPT]`).
  - No plaintext secrets or passwords stored in application codebase.

### 2.5 [D] Denial of Service (Availability Interruption)
- **Threat:** Exhaustion of database file locks or web application threads causing portal downtime.
- **Attack Vector:** Submitting excessively large queries or locking the local SQLite database.
- **Impact:** System downtime preventing students or examiners from accessing the lab.
- **Mitigation:**
  - Connection isolation and closure in `finally:` blocks.
  - Lightweight SQLite operations with minimal overhead.

### 2.6 [E] Elevation of Privilege (Unauthorized Authorization)
- **Threat:** An `ANALYST` role user accesses administrator endpoints (e.g. `/admin/dashboard`, `/database`).
- **Attack Vector:** Direct URL navigation bypassing client-side navigation menus.
- **Impact:** Unauthorized users gain administrative privileges and full data access.
- **Mitigation:**
  - Strict server-side `@role_required(['ADMIN'])` decorator enforcing role checks at the controller level.
  - Immediate rejection with HTTP 403 Forbidden and audit trail logging.

---

## 3. Trust Boundaries
1. **Boundary A (External Browser to Flask Controller):** Untrusted boundary. All inputs must be validated, sanitized, and authenticated.
2. **Boundary B (Flask Controller to SQLite Database):** Semi-trusted boundary. All SQL queries must be parameterized to prevent code-data mixing.
3. **Boundary C (Database to Browser Response):** Semi-trusted boundary. All output rendered in HTML templates must be auto-escaped to prevent DOM-based XSS.
