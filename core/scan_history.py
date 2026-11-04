import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

RESULTS_DB = Path("scanner_history.db")


def _get_connection(db_path: Path = RESULTS_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    """Create tables if they don't exist."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256 TEXT UNIQUE NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            verdict TEXT NOT NULL,
            detected_mime_type TEXT,
            size_bytes INTEGER,
            reasons TEXT,
            scanned_at TEXT NOT NULL,
            scanner_version TEXT DEFAULT '0.1.0',
            quarantine TEXT DEFAULT NULL,
            report_path TEXT DEFAULT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at)
    """)
    conn.commit()


def init_db(db_path: Path = RESULTS_DB) -> None:
    """Initialize the scan history database."""
    conn = _get_connection(db_path)
    _init_db(conn)
    conn.close()


def record_scan(
    sha256: str,
    file_name: str,
    file_path: str,
    verdict: str,
    detected_mime_type: str,
    size_bytes: int,
    reasons: List[str],
    scanned_at: str,
    scanner_version: str = "0.1.0",
    quarantine: Optional[str] = None,
    report_path: Optional[str] = None,
) -> None:
    """Record a scan result in the history database."""
    conn = _get_connection()
    try:
        _init_db(conn)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT OR REPLACE INTO scans
               (sha256, file_name, file_path, verdict, detected_mime_type,
                size_bytes, reasons, scanned_at, scanner_version,
                quarantine, report_path)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sha256,
                file_name,
                file_path,
                verdict,
                detected_mime_type,
                size_bytes,
                "|".join(reasons) if reasons else "",
                scanned_at,
                scanner_version,
                quarantine,
                report_path,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan(sha256: str) -> Optional[Dict[str, Any]]:
    """Retrieve a scan result by SHA-256 hash."""
    conn = _get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE sha256 = ?", (sha256,))
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        conn.close()


def get_scans_by_verdict(
    verdict: str, limit: int = 100
) -> List[Dict[str, Any]]:
    """Retrieve scans filtered by verdict."""
    conn = _get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM scans WHERE verdict = ? ORDER BY scanned_at DESC LIMIT ?",
            (verdict, limit),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve most recent scans."""
    conn = _get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def delete_scan(sha256: str) -> bool:
    """Delete a scan record by SHA-256."""
    conn = _get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE sha256 = ?", (sha256,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def search_scans(
    query: str, limit: int = 50
) -> List[Dict[str, Any]]:
    """Search scans by file name or reasons."""
    conn = _get_connection()
    try:
        cursor = conn.cursor()
        like_query = f"%{query}%"
        cursor.execute(
            """SELECT * FROM scans
               WHERE file_name LIKE ? OR reasons LIKE ?
               ORDER BY scanned_at DESC LIMIT ?""",
            (like_query, like_query, limit),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()