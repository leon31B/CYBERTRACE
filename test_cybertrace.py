"""
Automated Verification & Security Test Suite for CYBERTRACE
Validates authentication, RBAC, CRUD operations, error handlers,
and all five security lab before/after demonstrations.
"""
import sys
from app import app
import database

def run_tests():
    print("=" * 65)
    print(" CYBERTRACE Comprehensive Automated Verification Suite")
    print("=" * 65)
    
    client = app.test_client()
    passed = 0
    total = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f" [PASS] {name}")
        else:
            print(f" [FAIL] {name} - {details}")

    # 1. Unauthenticated Redirection
    res = client.get('/dashboard')
    assert_test("Unauthenticated access to /dashboard redirects to /login", 
                res.status_code == 302 and '/login' in res.headers.get('Location', ''))

    res = client.get('/cases')
    assert_test("Unauthenticated access to /cases redirects to /login", 
                res.status_code == 302 and '/login' in res.headers.get('Location', ''))

    # 2. Authentication: Failed Login
    res = client.post('/login', data={'username': 'admin', 'password': 'invalid_password'}, follow_redirects=True)
    assert_test("Failed login rejects wrong password with flash message", 
                b'Invalid credentials' in res.data and res.status_code == 200)

    res = client.post('/login', data={'username': 'nonexistent_user', 'password': 'password123'}, follow_redirects=True)
    assert_test("Failed login rejects non-existent user", 
                b'Invalid credentials' in res.data)

    # 3. Authentication: Analyst Login
    with client.session_transaction() as sess:
        sess.clear()
    res = client.post('/login', data={'username': 'analyst', 'password': 'analyst123'}, follow_redirects=True)
    assert_test("Analyst login succeeds with valid credentials", 
                b'Analyst Liam Ross' in res.data and b'SOC Operations' in res.data)

    # 4. RBAC: Analyst Forbidden Access Tests (HTTP 403)
    res = client.get('/database')
    assert_test("Analyst blocked from /database with HTTP 403", 
                res.status_code == 403 and b'Clearance Level Insufficient' in res.data)

    res = client.get('/admin/dashboard')
    assert_test("Analyst blocked from /admin/dashboard with HTTP 403", res.status_code == 403)

    res = client.get('/admin/users')
    assert_test("Analyst blocked from /admin/users with HTTP 403", res.status_code == 403)

    res = client.get('/cases/new')
    assert_test("Analyst blocked from creating new cases with HTTP 403", res.status_code == 403)

    res = client.get('/evidence/new')
    assert_test("Analyst blocked from adding evidence with HTTP 403", res.status_code == 403)

    # 5. Core Operational Routes as Authenticated User
    res = client.get('/cases')
    assert_test("Cases catalog renders HTTP 200", res.status_code == 200 and b'CASE-001' in res.data)

    res = client.get('/cases/1')
    assert_test("Case dossier /cases/1 renders HTTP 200 with evidence and notes", 
                res.status_code == 200 and b'Unauthorized Ingress' in res.data)

    res = client.get('/evidence')
    assert_test("Evidence locker renders HTTP 200", 
                res.status_code == 200 and b'EVD-DISK-001' in res.data)

    res = client.get('/investigators')
    assert_test("Investigators directory renders HTTP 200", 
                res.status_code == 200 and b'Director Marcus Vance' in res.data)

    res = client.get('/profile')
    assert_test("Operator profile page renders HTTP 200", 
                res.status_code == 200 and b'Analyst Liam Ross' in res.data)

    # 6. Documentation & Threat Model Pages
    res = client.get('/security')
    assert_test("Security assessment dashboard renders HTTP 200", 
                res.status_code == 200 and b'Security Fix &amp; Mitigation Master Matrix' in res.data)

    res = client.get('/security/attack-surface')
    assert_test("Attack Surface page renders HTTP 200 with visual boundary map", 
                res.status_code == 200 and b'Visual Attack Surface Map' in res.data)

    res = client.get('/security/threat-model')
    assert_test("Threat Model page renders HTTP 200 with STRIDE matrix", 
                res.status_code == 200 and b'STRIDE Threat Classification Matrix' in res.data)

    # 7. Lab 1: SQL Injection (SQLi)
    res = client.post('/security/sqli', data={'mode': 'vulnerable', 'search_val': "' OR '1'='1"}, follow_redirects=True)
    assert_test("SQLi vulnerable mode executes string concatenation and returns sandbox records", 
                b'REC-9001' in res.data and b'Raw SQL Query Executed' in res.data)

    res = client.post('/security/sqli', data={'mode': 'secure', 'search_val': "' OR '1'='1"}, follow_redirects=True)
    assert_test("SQLi secure mode parameterizes input and neutralizes attack", 
                b'Attack Neutralized' in res.data and b'Zero records matched' in res.data)

    # 8. Lab 2: Cross-Site Scripting (XSS)
    res = client.post('/security/xss', data={'payload': '<b>CYBERTRACE TEST</b>', 'mode': 'reflected'}, follow_redirects=True)
    assert_test("XSS lab renders both unescaped markup and safe auto-escaped HTML entity", 
                b'<b>CYBERTRACE TEST</b>' in res.data and b'&lt;b&gt;CYBERTRACE TEST&lt;/b&gt;' in res.data)

    # 9. Lab 3: Cross-Site Request Forgery (CSRF)
    res = client.get('/security/csrf')
    assert_test("CSRF lab renders HTTP 200", res.status_code == 200 and b'Cross-Site Request Forgery' in res.data)

    res = client.post('/demo/csrf/vulnerable_update', data={'department': 'Insecure Dept'}, follow_redirects=True)
    assert_test("Vulnerable CSRF endpoint accepts request without token", 
                b'without CSRF validation' in res.data)

    res = client.post('/demo/csrf/secure_update', data={'department': 'Blocked Dept'}, follow_redirects=True)
    assert_test("Secure CSRF endpoint rejects request missing token", 
                b'Request BLOCKED' in res.data)

    # Extract valid CSRF token from active session and test valid submission
    with client.session_transaction() as sess:
        valid_csrf = sess.get('csrf_token')
    res = client.post('/demo/csrf/secure_update', data={'csrf_token': valid_csrf, 'department': 'Verified SOC Unit'}, follow_redirects=True)
    assert_test("Secure CSRF endpoint accepts request with valid token", 
                b'Request ACCEPTED' in res.data)

    # 10. Lab 4: Broken Access Control
    res = client.get('/demo/access_control/unprotected_admin_file')
    assert_test("Unprotected admin file allows low-privileged analyst access", 
                b'VULNERABILITY CONFIRMED' in res.data and res.status_code == 200)

    res = client.get('/demo/access_control/protected_admin_file')
    assert_test("Protected admin file rejects analyst with HTTP 403 Forbidden", 
                res.status_code == 403)

    # 11. Lab 5: Sensitive Information Disclosure
    res = client.get('/security/information-disclosure')
    assert_test("Information Disclosure lab renders HTTP 200", res.status_code == 200)

    res = client.get('/demo/info_disclosure/leak')
    assert_test("Simulated leak endpoint demonstrates verbose traceback with fictional DEMO keys", 
                b'SIMULATED RAW TRACEBACK DUMP' in res.data and b'DEMO_SECRET_KEY' in res.data)

    # 12. Investigator Capabilities
    client.get('/logout')
    client.post('/login', data={'username': 'investigator', 'password': 'investigator123'}, follow_redirects=True)
    
    res = client.get('/cases/new')
    assert_test("Investigator is authorized to access /cases/new (HTTP 200)", res.status_code == 200)

    res = client.get('/evidence/new')
    assert_test("Investigator is authorized to access /evidence/new (HTTP 200)", res.status_code == 200)

    # 13. Admin Capabilities & Database Inspector
    client.get('/logout')
    client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    
    res = client.get('/database')
    assert_test("Admin accesses /database successfully (HTTP 200)", 
                res.status_code == 200 and b'Classroom Database Record Inspector' in res.data)
    assert_test("Database viewer strictly masks passwords as [HASHED-PBKDF2/SCRYPT]", 
                b'[HASHED-PBKDF2/SCRYPT]' in res.data)

    res = client.get('/admin/dashboard')
    assert_test("Admin accesses /admin/dashboard successfully (HTTP 200)", res.status_code == 200)

    res = client.get('/admin/users')
    assert_test("Admin accesses /admin/users successfully (HTTP 200)", res.status_code == 200)

    res = client.get('/demo/access_control/protected_admin_file')
    assert_test("Admin accesses protected admin file with HTTP 200 and JSON payload", 
                res.status_code == 200 and b'SECURE AUTHORIZATION VERIFIED' in res.data)

    # 14. Custom Error Handling
    res = client.get('/nonexistent_url_dossier_404')
    assert_test("Custom 404 Not Found error template renders", 
                res.status_code == 404 and b'404' in res.data)

    # 15. Audit Log Generation Verification
    recent_audit = database.query_db("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1", one=True)
    assert_test("Audit logs successfully record system actions in SQLite", 
                recent_audit is not None and len(recent_audit['action']) > 0)

    print("=" * 65)
    print(f" FINAL TEST RESULT: {passed}/{total} ASSERTIONS PASSED")
    print("=" * 65)

    if passed == total:
        print("[+] ALL VERIFICATION TESTS PASSED SUCCESSFULLY!")
        return 0
    else:
        print("[-] SOME TESTS FAILED.")
        return 1

if __name__ == '__main__':
    sys.exit(run_tests())
