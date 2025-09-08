import sqlite3
import os
from werkzeug.security import generate_password_hash


def init_db():
    conn = sqlite3.connect("llm_logs.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            prompt_encrypted TEXT NOT NULL,
            response_encrypted TEXT NOT NULL,
            previous_hash TEXT,
            current_hash TEXT NOT NULL,
            signature TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )
    # Multi-sig: registered public keys
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS msig_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signer TEXT UNIQUE NOT NULL,
            pub_key_base64 TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            rotated_at TEXT
        )
        """
    )
    # Multi-sig: high-risk operations
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS msig_ops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            op_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            timelock_secs INTEGER NOT NULL DEFAULT 600,
            quorum_required INTEGER NOT NULL DEFAULT 2,
            created_at TEXT NOT NULL,
            quorum_met_at TEXT,
            execute_not_before TEXT
        )
        """
    )
    # Multi-sig: approvals per signer
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS msig_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            op_id INTEGER NOT NULL,
            signer TEXT NOT NULL,
            sig_base64 TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            valid INTEGER NOT NULL DEFAULT 0,
            reason TEXT,
            UNIQUE(op_id, signer)
        )
        """
    )
    conn.commit()
    conn.close()


def ensure_default_admin():
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD", "adminpass")
    role = "admin"
    conn = sqlite3.connect("llm_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if row is None:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        conn.commit()
    conn.close()


def get_user(username: str):
    conn = sqlite3.connect("llm_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {"username": row[0], "password_hash": row[1], "role": row[2]}


init_db()
ensure_default_admin()