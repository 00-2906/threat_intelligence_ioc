"""
db.py — Tiny Postgres layer for scan history.

Phase 5. Deliberately plain (psycopg2, no ORM) — this project has
enough new concepts coming later (Isolation Forest, RAG, graphs); the
storage layer doesn't need to be one of them.
"""
import json
import os
import logging
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
psycopg2 = None

if not DATABASE_URL:
    logger.warning(
        "DATABASE_URL is not set. Add DATABASE_URL=... to your .env file. "
        "Database operations will be skipped. "
        "Example: DATABASE_URL=postgresql://user:password@localhost:5432/ioc_scanner"
    )
else:
    try:
        import psycopg2
        import psycopg2.extras
        logger.info("psycopg2 loaded successfully")
    except ImportError:
        logger.warning("psycopg2 not installed. Run: pip install psycopg2-binary")
        psycopg2 = None


def get_conn():
    if not DATABASE_URL or psycopg2 is None:
        return None
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        return None


def init_db() -> None:
    conn = get_conn()
    if conn is None:
        logger.warning("Database not configured, skipping init_db")
        return
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id SERIAL PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    risk_score REAL,
                    risk_label TEXT,
                    scanned_at TIMESTAMPTZ NOT NULL,
                    raw_data JSONB
                )
                """
            )
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
    finally:
        if conn:
            conn.close()


def save_scan(ioc_type: str, value: str, risk_score: float, risk_label: str, raw_data: dict) -> None:
    conn = get_conn()
    if conn is None:
        logger.debug(f"Database not available, scan not saved: {value}")
        return
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (ioc_type, value, risk_score, risk_label, scanned_at, raw_data)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    ioc_type,
                    value,
                    risk_score,
                    risk_label,
                    datetime.now(timezone.utc),
                    json.dumps(raw_data),
                ),
            )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to save scan: {e}")
    finally:
        if conn:
            conn.close()


def get_history(limit: int = 50) -> list[dict]:
    conn = get_conn()
    if conn is None:
        logger.debug("Database not available, returning empty history")
        return []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, ioc_type, value, risk_score, risk_label, scanned_at
                FROM scans
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Failed to retrieve history: {e}")
        return []
    finally:
        if conn:
            conn.close()
