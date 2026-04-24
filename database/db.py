"""
database/db.py — Upgraded Database Layer
"""

import sqlite3
import time

DB_NAME = "secure_auth.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _column_exists(cursor, table: str, column: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row["name"] == column for row in cursor.fetchall())


def create_user_table():
    conn = get_connection()
    cursor = conn.cursor()

    # Core users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username        TEXT PRIMARY KEY,
            password        TEXT NOT NULL,
            role            TEXT NOT NULL,
            otp_secret      TEXT NOT NULL
        )
    ''')

    # Migrate: add new columns if they don't exist (safe upgrade)
    migrations = [
        ("users",          "failed_attempts", "INTEGER DEFAULT 0"),
        ("users",          "last_login",       "REAL DEFAULT 0"),
        ("users",          "is_locked",        "INTEGER DEFAULT 0"),
        ("users",          "security_score",   "INTEGER DEFAULT 0"),
    ]
    for table, col, typedef in migrations:
        if not _column_exists(cursor, table, col):
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")

    # Login attempts table (for brute-force tracking)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            username     TEXT PRIMARY KEY,
            attempts     INTEGER DEFAULT 0,
            last_attempt REAL    DEFAULT 0
        )
    ''')

    # Security events log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  REAL    NOT NULL,
            event_type TEXT    NOT NULL,
            username   TEXT,
            message    TEXT    NOT NULL,
            severity   TEXT    DEFAULT 'INFO',
            flags      INTEGER DEFAULT 0
        )
    ''')

    conn.commit()
    conn.close()


def save_user(user_dict):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (username, password, role, otp_secret, failed_attempts, last_login, is_locked, security_score)
        VALUES (?, ?, ?, ?, 0, 0, 0, 0)
    ''', (user_dict["username"], user_dict["password"], user_dict["role"], user_dict["otp_secret"]))
    conn.commit()
    conn.close()


def get_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        d = dict(row)
        # Ensure new fields exist (graceful for old DBs before migration runs)
        d.setdefault("failed_attempts", 0)
        d.setdefault("last_login", 0)
        d.setdefault("is_locked", 0)
        d.setdefault("security_score", 0)
        return d
    return None


def update_last_login(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET last_login = ? WHERE username = ?',
        (time.time(), username)
    )
    conn.commit()
    conn.close()


def update_security_score(username, score: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET security_score = ? WHERE username = ?',
        (score, username)
    )
    conn.commit()
    conn.close()


def lock_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_locked = 1 WHERE username = ?', (username,))
    conn.commit()
    conn.close()


def unlock_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_locked = 0 WHERE username = ?', (username,))
    conn.commit()
    conn.close()


# ── Login Attempts ─────────────────────────────────────────────────

def get_failed_attempts(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT attempts, last_attempt FROM login_attempts WHERE username = ?',
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["attempts"], row["last_attempt"]
    return 0, 0.0


def increment_failed_attempts(username, current_time):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT attempts FROM login_attempts WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result:
        new_attempts = result["attempts"] + 1
        cursor.execute(
            'UPDATE login_attempts SET attempts = ?, last_attempt = ? WHERE username = ?',
            (new_attempts, current_time, username)
        )
    else:
        new_attempts = 1
        cursor.execute(
            'INSERT INTO login_attempts (username, attempts, last_attempt) VALUES (?, ?, ?)',
            (username, new_attempts, current_time)
        )

    conn.commit()
    conn.close()
    return new_attempts


def reset_failed_attempts(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE login_attempts SET attempts = 0, last_attempt = 0 WHERE username = ?',
        (username,)
    )
    conn.commit()
    conn.close()


# ── Security Events ────────────────────────────────────────────────

def log_security_event(event_type: str, message: str, username: str = None,
                        severity: str = "INFO", flags: int = 0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO security_events (timestamp, event_type, username, message, severity, flags)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (time.time(), event_type, username, message, severity, flags))
    conn.commit()
    conn.close()


def get_recent_security_events(limit: int = 20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM security_events
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]