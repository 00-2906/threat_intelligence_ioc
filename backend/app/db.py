"""
db.py — Tiny SQLite layer for scan history.

Phase 5. Deliberately plain (stdlib sqlite3, no ORM) — this project has
enough new concepts coming later (Isolation Forest, RAG, graphs); the
storage layer doesn't need to be one of them.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "scans.db"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            risk_score REAL,
            risk_label TEXT,
            scanned_at TEXT NOT NULL,
            raw_data TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(ioc_type: str, value: str, risk_score: float, risk_label: str, raw_data: dict) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO scans (ioc_type, value, risk_score, risk_label, scanned_at, raw_data)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            ioc_type,
            value,
            risk_score,
            risk_label,
            datetime.now(timezone.utc).isoformat(),
            json.dumps(raw_data),
        ),
    )
    conn.commit()
    conn.close()


def get_history(limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, ioc_type, value, risk_score, risk_label, scanned_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]
