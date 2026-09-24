import sqlite3
import os
from datetime import datetime

# Local database file path
DB_PATH = os.path.join(os.path.dirname(__file__), 'cybertrace.db')

def get_db_connection():
    """
    Establish a connection to the local SQLite database.
    Configured with sqlite3.Row for dict-like column access.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    """
    Safely execute a SELECT query and return rows.
    Uses parameterized queries for secure operations.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(query, args)
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()

def execute_db(query, args=()):
    """
    Safely execute an INSERT/UPDATE/DELETE query and commit changes.
    Returns the last row id if available.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(query, args)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def log_audit(user_id, action, ip_address="127.0.0.1"):
    """
    Record internal audit trail event.
    Passwords and sensitive tokens are strictly never logged.
    """
    try:
        execute_db(
            "INSERT INTO audit_logs (user_id, action, ip_address, created_at) VALUES (?, ?, ?, ?)",
            (user_id, action, ip_address, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
    except Exception as e:
        print(f"[AUDIT LOG ERROR] Failed to record audit log: {e}")
