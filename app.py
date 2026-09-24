"""
CYBERTRACE — Digital Investigation & Web Security Assessment Lab
Main Flask Application Controller
Strictly localhost-only educational laboratory.
"""
import os
import secrets
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash
import database

app = Flask(__name__)
# Cryptographic secret key for session signing
app.secret_key = os.environ.get('CYBERTRACE_SECRET_KEY', secrets.token_hex(32))

# ---------------------------------------------------------
# CSRF & Template Context Processors
# ---------------------------------------------------------
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

@app.context_processor
def inject_global_template_data():
    """Inject CSRF token, current user info, and lab metadata into all templates."""
    return {
        'csrf_token': generate_csrf_token(),
        'current_user': {
            'id': session.get('user_id'),
            'username': session.get('username'),
            'role': session.get('role'),
            'full_name': session.get('full_name'),
            'department': session.get('department')
        } if 'user_id' in session else None,
        'current_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# ---------------------------------------------------------
# Authorization Decorators
# ---------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Authentication required. Please log in to access this portal.", "warning")
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Authentication required.", "warning")
                return redirect(url_for('login'))
            user_role = session.get('role')
            if user_role not in allowed_roles:
                database.log_audit(
                    session.get('user_id'),
                    f"UNAUTHORIZED_ACCESS_BLOCKED: Attempted access to {request.path} with role {user_role}",
                    request.remote_addr
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('login.html')

        user = database.query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)

        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            session['department'] = user['department']
            session['csrf_token'] = secrets.token_hex(16)

            database.log_audit(user['id'], f"USER_LOGIN: Successful authentication for {username}", request.remote_addr)
            flash(f"Welcome back, {user['full_name']} ({user['role']}).", "success")

            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            database.log_audit(None, f"AUTH_FAILURE: Failed login attempt for username '{username}'", request.remote_addr)
            flash("Invalid credentials. Please verify your demonstration username and password.", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    username = session.get('username', 'Anonymous')
    if user_id:
        database.log_audit(user_id, f"USER_LOGOUT: {username} signed out", request.remote_addr)
    session.clear()
    flash("You have been securely signed out.", "info")
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = database.query_db("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
    
    if request.method == 'POST':
        # Validate CSRF Token
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            flash("Security Exception: CSRF token validation failed.", "danger")
            return redirect(url_for('profile'))

        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        department = request.form.get('department', '').strip()
        new_password = request.form.get('new_password', '').strip()

        if not full_name or not email:
            flash("Full name and email cannot be blank.", "warning")
            return render_template('profile.html', user=user)

        if new_password:
            new_hash = generate_password_hash(new_password)
            database.execute_db("""
                UPDATE users SET full_name = ?, email = ?, department = ?, password_hash = ?
                WHERE id = ?
            """, (full_name, email, department, new_hash, session['user_id']))
            database.log_audit(session['user_id'], "PROFILE_UPDATE: Profile and password updated", request.remote_addr)
        else:
            database.execute_db("""
                UPDATE users SET full_name = ?, email = ?, department = ?
                WHERE id = ?
            """, (full_name, email, department, session['user_id']))
            database.log_audit(session['user_id'], "PROFILE_UPDATE: Profile information updated", request.remote_addr)

        session['full_name'] = full_name
        session['department'] = department
        flash("Profile updated successfully.", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# ---------------------------------------------------------
# Main SOC Dashboard & Portal Pages
# ---------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    total_cases = database.query_db("SELECT COUNT(*) as cnt FROM cases", one=True)['cnt']
    open_cases = database.query_db("SELECT COUNT(*) as cnt FROM cases WHERE status != 'CLOSED'", one=True)['cnt']
    evidence_count = database.query_db("SELECT COUNT(*) as cnt FROM evidence", one=True)['cnt']
    audit_count = database.query_db("SELECT COUNT(*) as cnt FROM audit_logs", one=True)['cnt']
    
    recent_cases = database.query_db("""
        SELECT c.*, u.full_name as investigator_name 
        FROM cases c 
        LEFT JOIN users u ON c.assigned_to = u.id 
        ORDER BY c.id DESC LIMIT 5
    """)
    
    recent_audits = database.query_db("""
        SELECT a.*, u.username 
        FROM audit_logs a 
        LEFT JOIN users u ON a.user_id = u.id 
        ORDER BY a.id DESC LIMIT 6
    """)

    database.log_audit(session['user_id'], "DASHBOARD_ACCESS: SOC Dashboard loaded", request.remote_addr)

    return render_template(
        'dashboard.html',
        total_cases=total_cases,
        open_cases=open_cases,
        evidence_count=evidence_count,
        audit_count=audit_count,
        recent_cases=recent_cases,
        recent_audits=recent_audits
    )

@app.route('/cases')
@login_required
def cases():
    search_query = request.args.get('q', '').strip()
    severity_filter = request.args.get('severity', '').strip()

    sql = """
        SELECT c.*, u.full_name as investigator_name 
        FROM cases c 
        LEFT JOIN users u ON c.assigned_to = u.id 
        WHERE 1=1
    """
    params = []

    if search_query:
        sql += " AND (c.case_number LIKE ? OR c.title LIKE ? OR c.description LIKE ?)"
        term = f"%{search_query}%"
        params.extend([term, term, term])

    if severity_filter:
        sql += " AND c.severity = ?"
        params.append(severity_filter)

    sql += " ORDER BY c.id DESC"
    all_cases = database.query_db(sql, params)

    database.log_audit(session['user_id'], f"CASE_SEARCH: Searched with q='{search_query}', sev='{severity_filter}'", request.remote_addr)
    return render_template('cases.html', cases=all_cases, search_query=search_query, severity_filter=severity_filter)

@app.route('/cases/new', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'INVESTIGATOR'])
def new_case():
    if request.method == 'POST':
        case_number = request.form.get('case_number', '').strip()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', 'MEDIUM')
        status = request.form.get('status', 'OPEN')
        assigned_to = request.form.get('assigned_to')

        if not case_number or not title:
            flash("Case number and title are required.", "danger")
            investigators = database.query_db("SELECT id, full_name, role FROM users WHERE role IN ('INVESTIGATOR', 'ADMIN')")
            return render_template('admin/cases.html', action='new', investigators=investigators)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            database.execute_db("""
                INSERT INTO cases (case_number, title, description, status, severity, assigned_to, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (case_number, title, description, status, severity, assigned_to, now))
            database.log_audit(session['user_id'], f"CASE_CREATE: Created case {case_number}", request.remote_addr)
            flash(f"Case {case_number} registered successfully.", "success")
            return redirect(url_for('cases'))
        except Exception as e:
            flash(f"Error creating case (duplicate case number?): {e}", "danger")

    investigators = database.query_db("SELECT id, full_name, role FROM users WHERE role IN ('INVESTIGATOR', 'ADMIN')")
    return render_template('admin/cases.html', action='new', investigators=investigators)

@app.route('/cases/<int:case_id>')
@login_required
def case_detail(case_id):
    case = database.query_db("""
        SELECT c.*, u.full_name as investigator_name, u.email as investigator_email 
        FROM cases c 
        LEFT JOIN users u ON c.assigned_to = u.id 
        WHERE c.id = ?
    """, (case_id,), one=True)

    if not case:
        abort(404)

    evidence_items = database.query_db("SELECT * FROM evidence WHERE case_id = ? ORDER BY id DESC", (case_id,))
    notes = database.query_db("""
        SELECT n.*, u.full_name, u.role 
        FROM investigation_notes n 
        JOIN users u ON n.user_id = u.id 
        WHERE n.case_id = ? 
        ORDER BY n.id DESC
    """, (case_id,))

    database.log_audit(session['user_id'], f"CASE_VIEW: Opened {case['case_number']}", request.remote_addr)
    return render_template('case_detail.html', case=case, evidence_items=evidence_items, notes=notes)

@app.route('/cases/<int:case_id>/add_note', methods=['POST'])
@login_required
def add_case_note(case_id):
    note = request.form.get('note', '').strip()
    if not note:
        flash("Note content cannot be empty.", "warning")
        return redirect(url_for('case_detail', case_id=case_id))

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    database.execute_db("""
        INSERT INTO investigation_notes (case_id, user_id, note, created_at)
        VALUES (?, ?, ?, ?)
    """, (case_id, session['user_id'], note, now))

    database.log_audit(session['user_id'], f"NOTE_ADDED: Added note to Case ID {case_id}", request.remote_addr)
    flash("Investigation note appended to log.", "success")
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/evidence')
@login_required
def evidence():
    items = database.query_db("""
        SELECT e.*, c.case_number, c.title as case_title 
        FROM evidence e 
        LEFT JOIN cases c ON e.case_id = c.id 
        ORDER BY e.id DESC
    """)
    database.log_audit(session['user_id'], "EVIDENCE_ACCESS: Evidence catalog viewed", request.remote_addr)
    return render_template('evidence.html', evidence_items=items)

@app.route('/evidence/new', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'INVESTIGATOR'])
def new_evidence():
    if request.method == 'POST':
        case_id = request.form.get('case_id')
        code = request.form.get('evidence_code', '').strip()
        desc = request.form.get('description', '').strip()
        etype = request.form.get('evidence_type', 'DIGITAL_LOG')
        status = request.form.get('status', 'SECURED')
        collected_by = session.get('full_name')

        if not code or not desc or not case_id:
            flash("All fields are required.", "danger")
            cases_list = database.query_db("SELECT id, case_number, title FROM cases")
            return render_template('admin/evidence.html', action='new', cases=cases_list)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            database.execute_db("""
                INSERT INTO evidence (case_id, evidence_code, description, evidence_type, status, collected_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (case_id, code, desc, etype, status, collected_by, now))
            database.log_audit(session['user_id'], f"EVIDENCE_RECORD: Logged evidence item {code}", request.remote_addr)
            flash(f"Evidence {code} secured in chain-of-custody.", "success")
            return redirect(url_for('evidence'))
        except Exception as e:
            flash(f"Error logging evidence (duplicate code?): {e}", "danger")

    cases_list = database.query_db("SELECT id, case_number, title FROM cases")
    return render_template('admin/evidence.html', action='new', cases=cases_list)

@app.route('/investigators')
@login_required
def investigators():
    team = database.query_db("SELECT id, username, full_name, email, role, department, created_at FROM users ORDER BY role ASC, full_name ASC")
    return render_template('investigators.html', team=team)

# ---------------------------------------------------------
# Database Viewer (Admin Classroom Inspection Tool)
# ---------------------------------------------------------
@app.route('/database')
@login_required
@role_required(['ADMIN'])
def database_viewer():
    # Fetch all tables safely
    users = database.query_db("SELECT id, username, '[HASHED-PBKDF2/SCRYPT]' as password_hash, role, full_name, email, department, created_at FROM users")
    cases_records = database.query_db("SELECT * FROM cases")
    evidence_records = database.query_db("SELECT * FROM evidence")
    notes_records = database.query_db("SELECT * FROM investigation_notes")
    audit_records = database.query_db("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50")
    demo_sqli = database.query_db("SELECT * FROM demo_sqli_records")

    database.log_audit(session['user_id'], "DATABASE_VIEWER_ACCESS: Admin viewed raw SQLite schema viewer", request.remote_addr)

    return render_template(
        'database_viewer.html',
        users=users,
        cases=cases_records,
        evidence=evidence_records,
        notes=notes_records,
        audit_logs=audit_records,
        demo_sqli=demo_sqli
    )

# ---------------------------------------------------------
# Security Assessment Overview, Attack Surface & Threat Model
# ---------------------------------------------------------
@app.route('/security')
@login_required
def security_dashboard():
    database.log_audit(session['user_id'], "SECURITY_DASHBOARD_ACCESS: Viewed security assessment matrix", request.remote_addr)
    return render_template('security/index.html')

@app.route('/security/attack-surface')
@login_required
def attack_surface():
    database.log_audit(session['user_id'], "SECURITY_DOC_VIEW: Reviewed Attack Surface Analysis", request.remote_addr)
    return render_template('security/attack_surface.html')

@app.route('/security/threat-model')
@login_required
def threat_model():
    database.log_audit(session['user_id'], "SECURITY_DOC_VIEW: Reviewed Threat Model & STRIDE Matrix", request.remote_addr)
    return render_template('security/threat_model.html')

# ---------------------------------------------------------
# LAB 1: SQL Injection (SQLi)
# ---------------------------------------------------------
@app.route('/security/sqli', methods=['GET', 'POST'])
@login_required
def sqli_lab():
    vulnerable_results = None
    vulnerable_query_str = None
    vulnerable_error = None
    
    secure_results = None
    secure_query_str = None
    
    mode = request.form.get('mode')
    input_val = request.form.get('search_val', '').strip()

    if request.method == 'POST' and input_val:
        database.log_audit(session['user_id'], f"SECURITY_TEST: SQLi Lab executed with mode='{mode}'", request.remote_addr)
        
        if mode == 'vulnerable':
            # INTENTIONALLY UNSAFE STRING CONCATENATION DEMONSTRATION (SANDBOX TABLE ONLY)
            vulnerable_query_str = f"SELECT record_id, title, classification, target_ip, notes FROM demo_sqli_records WHERE record_id = '{input_val}' OR classification = '{input_val}'"
            conn = database.get_db_connection()
            try:
                cur = conn.cursor()
                # Unsafe execution of raw string query
                cur.execute(vulnerable_query_str)
                vulnerable_results = cur.fetchall()
            except Exception as e:
                vulnerable_error = str(e)
            finally:
                conn.close()

        elif mode == 'secure':
            # SECURE PARAMETERIZED QUERY (STANDARD PRODUCTION PRACTICE)
            secure_query_str = "SELECT record_id, title, classification, target_ip, notes FROM demo_sqli_records WHERE record_id = ? OR classification = ?"
            secure_results = database.query_db(secure_query_str, (input_val, input_val))

    return render_template(
        'security/sqli.html',
        vulnerable_results=vulnerable_results,
        vulnerable_query=vulnerable_query_str,
        vulnerable_error=vulnerable_error,
        secure_results=secure_results,
        secure_query=secure_query_str,
        input_val=input_val,
        mode=mode
    )

# ---------------------------------------------------------
# LAB 2: Cross-Site Scripting (XSS)
# ---------------------------------------------------------
@app.route('/security/xss', methods=['GET', 'POST'])
@login_required
def xss_lab():
    reflected_payload = request.form.get('payload', '') if request.method == 'POST' else ''
    mode = request.form.get('mode', 'reflected')

    if request.method == 'POST':
        database.log_audit(session['user_id'], f"SECURITY_TEST: XSS Lab executed ({mode})", request.remote_addr)

    # Fetch recent notes for stored XSS context demonstration
    stored_notes = database.query_db("""
        SELECT n.*, u.full_name 
        FROM investigation_notes n 
        JOIN users u ON n.user_id = u.id 
        ORDER BY n.id DESC LIMIT 4
    """)

    return render_template(
        'security/xss.html',
        payload=reflected_payload,
        stored_notes=stored_notes,
        mode=mode
    )

# ---------------------------------------------------------
# LAB 3: Cross-Site Request Forgery (CSRF)
# ---------------------------------------------------------
@app.route('/security/csrf')
@login_required
def csrf_lab():
    user = database.query_db("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
    return render_template('security/csrf.html', user=user)

@app.route('/demo/csrf/vulnerable_update', methods=['POST'])
@login_required
def demo_csrf_vulnerable():
    """
    LOCAL VULNERABLE DEMONSTRATION
    State-changing POST request WITHOUT CSRF token validation.
    """
    new_dept = request.form.get('department', 'Unspecified Branch')
    database.execute_db("UPDATE users SET department = ? WHERE id = ?", (new_dept, session['user_id']))
    session['department'] = new_dept
    database.log_audit(session['user_id'], f"SECURITY_TEST: Vulnerable CSRF executed (Updated dept to '{new_dept}')", request.remote_addr)
    flash(f"[VULNERABLE DEMO] Department state changed to '{new_dept}' without CSRF validation!", "danger")
    return redirect(url_for('csrf_lab'))

@app.route('/demo/csrf/secure_update', methods=['POST'])
@login_required
def demo_csrf_secure():
    """
    SECURE IMPLEMENTATION
    Requires valid CSRF Synchronizer Token.
    """
    submitted_token = request.form.get('csrf_token')
    session_token = session.get('csrf_token')

    if not submitted_token or submitted_token != session_token:
        database.log_audit(session['user_id'], "SECURITY_DEFENSE: Blocked CSRF attempt (missing or invalid token)", request.remote_addr)
        flash("[SECURE DEMO] Request BLOCKED! CSRF token was invalid or missing. State change aborted.", "warning")
        return redirect(url_for('csrf_lab'))

    new_dept = request.form.get('department', 'Secure SOC Unit')
    database.execute_db("UPDATE users SET department = ? WHERE id = ?", (new_dept, session['user_id']))
    session['department'] = new_dept
    database.log_audit(session['user_id'], f"SECURITY_TEST: Secure CSRF validated (Updated dept to '{new_dept}')", request.remote_addr)
    flash(f"[SECURE DEMO] Request ACCEPTED! Valid CSRF Token verified. Department updated to '{new_dept}'.", "success")
    return redirect(url_for('csrf_lab'))

# ---------------------------------------------------------
# LAB 4: Broken Access Control (RBAC)
# ---------------------------------------------------------
@app.route('/security/access-control')
@login_required
def access_control_lab():
    return render_template('security/access_control.html')

@app.route('/demo/access_control/unprotected_admin_file')
@login_required
def demo_unprotected_admin_file():
    """
    LOCAL VULNERABLE DEMONSTRATION
    Broken Access Control: Missing role check allows ANALYST or INVESTIGATOR to view classified executive file.
    """
    database.log_audit(session['user_id'], f"SECURITY_TEST: Accessed UNPROTECTED admin asset with role '{session.get('role')}'", request.remote_addr)
    classified_data = {
        "file_name": "CLASSIFIED-CYBERTRACE-CORE-DEAL-007.DAT",
        "clearance_level": "LEVEL-5 STRICTLY ADMIN ONLY",
        "system_status": "VULNERABLE: Authorization check was omitted on this route!",
        "simulated_payload": "Encrypted Root Keystore Hash: 8f49a37e5... (Fictional Laboratory Asset)"
    }
    return jsonify({
        "status": "VULNERABILITY CONFIRMED",
        "message": f"User '{session.get('username')}' with non-admin role '{session.get('role')}' was granted access due to missing server-side role validation.",
        "data": classified_data
    })

@app.route('/demo/access_control/protected_admin_file')
@login_required
@role_required(['ADMIN'])
def demo_protected_admin_file():
    """
    SECURE IMPLEMENTATION
    Enforces strict server-side role check via decorator.
    """
    database.log_audit(session['user_id'], "SECURITY_TEST: Legitimate ADMIN accessed protected asset", request.remote_addr)
    return jsonify({
        "status": "SECURE AUTHORIZATION VERIFIED",
        "message": "Access granted: Caller successfully authenticated and verified with role 'ADMIN'.",
        "file_name": "CLASSIFIED-CYBERTRACE-CORE-DEAL-007.DAT",
        "clearance_level": "LEVEL-5 ADMIN CONFIRMED"
    })

# ---------------------------------------------------------
# LAB 5: Sensitive Information Disclosure
# ---------------------------------------------------------
@app.route('/security/information-disclosure')
@login_required
def information_disclosure_lab():
    return render_template('security/information_disclosure.html')

@app.route('/demo/info_disclosure/leak')
@login_required
def demo_leak():
    """
    LOCAL VULNERABLE DEMONSTRATION
    Demonstrates how verbose debug mode and unhandled exceptions expose internal paths and stack traces.
    """
    database.log_audit(session['user_id'], "SECURITY_TEST: Triggered vulnerable verbose exception demonstration", request.remote_addr)
    
    # Simulate a detailed unhandled exception dump with clearly fictional values
    mock_leaked_context = {
        "EXPOSED_ERROR": "OperationalError: unable to open database file",
        "INTERNAL_OS": "Simulated Lab Environment (Windows/Localhost)",
        "INTERNAL_PYTHON_PATH": "C:\\CYBERTRACE\\demo\\sqlite_core.py",
        "INTERNAL_DB_FILE_PATH": "C:\\CYBERTRACE\\demo\\demo_database.db",
        "DEMO_SECRET_KEY": "DEMO_SECRET_KEY_NOT_A_REAL_TOKEN",
        "DEMO_INTERNAL_PATH": "C:\\CYBERTRACE\\demo\\internal_config.yaml",
        "FRAME_STACK_TRACE": [
            'File "C:\\CYBERTRACE\\demo\\app.py", line 412, in demo_leak',
            'File "C:\\CYBERTRACE\\demo\\database.py", line 28, in execute_db',
            'sqlite3.OperationalError: simulated disk I/O failure for classroom demonstration'
        ]
    }
    return render_template('security/information_disclosure.html', leak_data=mock_leaked_context, mode='leak')

# ---------------------------------------------------------
# Admin Control Routes
# ---------------------------------------------------------
@app.route('/admin/dashboard')
@login_required
@role_required(['ADMIN'])
def admin_dashboard():
    users_count = database.query_db("SELECT COUNT(*) as cnt FROM users", one=True)['cnt']
    cases_count = database.query_db("SELECT COUNT(*) as cnt FROM cases", one=True)['cnt']
    evidence_count = database.query_db("SELECT COUNT(*) as cnt FROM evidence", one=True)['cnt']
    audit_logs = database.query_db("""
        SELECT a.*, u.username, u.role 
        FROM audit_logs a 
        LEFT JOIN users u ON a.user_id = u.id 
        ORDER BY a.id DESC LIMIT 15
    """)
    return render_template(
        'admin/dashboard.html',
        users_count=users_count,
        cases_count=cases_count,
        evidence_count=evidence_count,
        audit_logs=audit_logs
    )

@app.route('/admin/users')
@login_required
@role_required(['ADMIN'])
def admin_users():
    users_list = database.query_db("SELECT id, username, role, full_name, email, department, created_at FROM users")
    return render_template('admin/users.html', users=users_list)

@app.route('/admin/cases')
@login_required
@role_required(['ADMIN'])
def admin_cases():
    cases_list = database.query_db("""
        SELECT c.*, u.full_name as assigned_name 
        FROM cases c 
        LEFT JOIN users u ON c.assigned_to = u.id 
        ORDER BY c.id DESC
    """)
    investigators = database.query_db("SELECT id, full_name, role FROM users WHERE role IN ('INVESTIGATOR', 'ADMIN')")
    return render_template('admin/cases.html', cases=cases_list, investigators=investigators, action='list')

@app.route('/admin/evidence')
@login_required
@role_required(['ADMIN'])
def admin_evidence():
    evidence_list = database.query_db("""
        SELECT e.*, c.case_number 
        FROM evidence e 
        LEFT JOIN cases c ON e.case_id = c.id 
        ORDER BY e.id DESC
    """)
    cases_list = database.query_db("SELECT id, case_number, title FROM cases")
    return render_template('admin/evidence.html', evidence_items=evidence_list, cases=cases_list, action='list')

# ---------------------------------------------------------
# Custom Error Handlers (Secure Production Handling)
# ---------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    # Logs internal error details safely without leaking to end-user
    print(f"[SECURITY EVENT: 500 SERVER ERROR] Internal incident reference generated.")
    return render_template('errors/500.html'), 500

# ---------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------
if __name__ == '__main__':
    # Strictly bind to localhost for educational safety
    print("==================================================================")
    print(" CYBERTRACE: Digital Investigation & Web Security Assessment Lab  ")
    print(" Status: Active on http://127.0.0.1:5000                          ")
    print(" Mode: Localhost-only Educational Demonstration                   ")
    print("==================================================================")
    app.run(host='127.0.0.1', port=5000, debug=False)
