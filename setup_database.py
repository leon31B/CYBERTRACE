"""
CYBERTRACE - Database Initialization & Seed Script
Fictional localhost-only laboratory database setup.
"""
import sqlite3
import os
import sys
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'cybertrace.db')

def init_database(reset=False):
    print(f"[*] Initializing CYBERTRACE database at: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if reset:
        print("[!] Performing clean reset of existing tables...")
        for table in ['audit_logs', 'investigation_notes', 'evidence', 'cases', 'users', 'demo_sqli_records']:
            cursor.execute(f"DROP TABLE IF EXISTS {table}")
        conn.commit()
    
    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('ADMIN', 'INVESTIGATOR', 'ANALYST')),
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        department TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # 2. Cases Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_number TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('OPEN', 'INVESTIGATING', 'CLOSED')),
        severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
        assigned_to INTEGER,
        created_at TEXT NOT NULL,
        FOREIGN KEY (assigned_to) REFERENCES users (id)
    );
    """)

    # 3. Evidence Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_code TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        status TEXT NOT NULL,
        collected_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases (id)
    );
    """)

    # 4. Investigation Notes Table (Used for standard note tracking & XSS lab)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigation_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        note TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)

    # 5. Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # 6. Isolated SQL Injection Demo Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS demo_sqli_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        classification TEXT NOT NULL,
        target_ip TEXT NOT NULL,
        notes TEXT NOT NULL
    );
    """)

    conn.commit()

    # --- Seed Initial Data ---
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Seed Users
    users_data = [
        ('admin', generate_password_hash('admin123'), 'ADMIN', 'Director Marcus Vance', 'm.vance@cybertrace.local', 'Cyber Threat Operations', now),
        ('investigator', generate_password_hash('investigator123'), 'INVESTIGATOR', 'Agent Sarah Chen', 's.chen@cybertrace.local', 'Digital Forensics Unit', now),
        ('analyst', generate_password_hash('analyst123'), 'ANALYST', 'Analyst Liam Ross', 'l.ross@cybertrace.local', 'SOC Tier-1 Monitoring', now)
    ]

    for username, p_hash, role, full_name, email, dept, created in users_data:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO users (username, password_hash, role, full_name, email, department, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (username, p_hash, role, full_name, email, dept, created))
            print(f" [+] Created user: {username} (Role: {role})")

    # Seed Cases (Fictional Examples matching specification)
    cases_data = [
        ('CASE-001', 'Unauthorized Ingress on Staging Host', 'Automated anomaly detector triggered alert on inbound connection attempts to internal host 10.0.4.15.', 'OPEN', 'HIGH', 2, '2024-09-15 08:30:00'),
        ('CASE-002', 'Targeted Spear-Phishing Campaign', 'Multiple executive mailbox accounts received credential solicitation messages impersonating internal IT support.', 'INVESTIGATING', 'CRITICAL', 2, '2024-09-16 11:15:00'),
        ('CASE-003', 'Lateral Movement Detection in Segment B', 'Unusual SMB/RPC connection spikes between workstation cluster and internal file repository.', 'OPEN', 'MEDIUM', 3, '2024-09-18 14:00:00'),
        ('CASE-004', 'Ransomware Precursor Script Execution', 'PowerShell script execution flagged attempting Volume Shadow Copy manipulation on host WS-088.', 'CLOSED', 'CRITICAL', 1, '2024-09-10 16:45:00')
    ]

    for case_num, title, desc, status, sev, assigned, created in cases_data:
        cursor.execute("SELECT id FROM cases WHERE case_number = ?", (case_num,))
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO cases (case_number, title, description, status, severity, assigned_to, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (case_num, title, desc, status, sev, assigned, created))
            print(f" [+] Seeded case: {case_num}")

    # Seed Evidence
    evidence_data = [
        (1, 'EVD-DISK-001', 'Physical bitstream copy of Workstation WS-088 SSD', 'DISK_IMAGE', 'SECURED', 'Agent Sarah Chen', '2024-09-15 10:20:00'),
        (1, 'EVD-PCAP-002', 'Network packet capture during staging host anomaly window (500MB)', 'NETWORK_PCAP', 'ANALYZING', 'Agent Sarah Chen', '2024-09-15 10:45:00'),
        (2, 'EVD-EML-003', 'Raw RFC822 phishing email headers with forged DKIM signature', 'EMAIL_HEADERS', 'SECURED', 'Analyst Liam Ross', '2024-09-16 12:00:00'),
        (3, 'EVD-LOG-004', 'Windows Security Event Log export (Event IDs 4624, 4672, 4688)', 'LOG_ARCHIVE', 'SECURED', 'Analyst Liam Ross', '2024-09-18 15:30:00')
    ]

    for cid, code, desc, etype, status, collector, created in evidence_data:
        cursor.execute("SELECT id FROM evidence WHERE evidence_code = ?", (code,))
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO evidence (case_id, evidence_code, description, evidence_type, status, collected_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (cid, code, desc, etype, status, collector, created))
            print(f" [+] Seeded evidence: {code}")

    # Seed Investigation Notes
    notes_data = [
        (1, 2, 'Volatile memory dump verified against SHA-256 hash. No rootkit signatures identified in preliminary pass.', '2024-09-15 13:00:00'),
        (1, 2, 'Suspicious reverse TCP handshake identified pointing to internal staging IP 10.0.4.15 on port 8443.', '2024-09-15 14:30:00'),
        (2, 3, 'Sender IP trace indicates origin from anonymized VPN gateway. IP added to firewall perimeter blocklist.', '2024-09-16 14:10:00')
    ]

    for cid, uid, note, created in notes_data:
        cursor.execute("SELECT id FROM investigation_notes WHERE case_id = ? AND note = ?", (cid, note))
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO investigation_notes (case_id, user_id, note, created_at)
            VALUES (?, ?, ?, ?)
            """, (cid, uid, note, created))

    # Seed Audit Logs
    audit_data = [
        (1, 'SYSTEM_INITIALIZATION: Core database schema verified', '127.0.0.1', '2024-09-10 08:00:00'),
        (1, 'USER_LOGIN: Admin Marcus Vance logged in', '127.0.0.1', '2024-09-18 09:00:00'),
        (2, 'CASE_VIEW: Agent Sarah Chen accessed CASE-2024-001', '127.0.0.1', '2024-09-18 09:15:00'),
        (3, 'EVIDENCE_RECORD: Analyst Liam Ross submitted EVD-LOG-004', '127.0.0.1', '2024-09-18 15:35:00')
    ]

    for uid, action, ip, created in audit_data:
        cursor.execute("SELECT id FROM audit_logs WHERE action = ?", (action,))
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO audit_logs (user_id, action, ip_address, created_at)
            VALUES (?, ?, ?, ?)
            """, (uid, action, ip, created))

    # Seed Isolated SQLi Sandbox Records
    demo_sqli_data = [
        ('REC-9001', 'Perimeter Firewall Log Batch A', 'CONFIDENTIAL', '192.168.10.1', 'Routine perimeter port sweep observed from internal test address.'),
        ('REC-9002', 'Incident Report: VPN Credential Spray', 'RESTRICTED', '192.168.10.45', 'Spraying against Active Directory service account blocked after 5 attempts.'),
        ('REC-9003', 'Database Backup Integrity Check', 'INTERNAL_ONLY', '192.168.20.100', 'MD5 and SHA-256 integrity hash verification completed with zero deviations.'),
        ('REC-9004', 'Threat Intel Brief: APT-Simulation-Gamma', 'TOP_SECRET_DEMO', '10.50.1.20', 'Simulated adversary techniques matching MITRE ATT&CK T1059 and T1078.')
    ]

    for rec_id, title, classif, tip, notes in demo_sqli_data:
        cursor.execute("SELECT id FROM demo_sqli_records WHERE record_id = ?", (rec_id,))
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO demo_sqli_records (record_id, title, classification, target_ip, notes)
            VALUES (?, ?, ?, ?, ?)
            """, (rec_id, title, classif, tip, notes))

    conn.commit()
    conn.close()
    print("[+] Database initialization complete. All tables and seed data verified.")

if __name__ == '__main__':
    should_reset = '--reset' in sys.argv
    init_database(reset=should_reset)
