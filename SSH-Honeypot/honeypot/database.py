"""
honeypot/database.py — SQLite persistence layer.

Two tables:
  - attempts : every login attempt (IP, username, password, timestamp, geo)
  - commands : every command typed after a "successful" fake login

We use sqlite3 from stdlib — no ORM needed for this schema.
Thread safety: we open a new connection per call (check_same_thread=False
would work too but per-call is simpler and avoids locking issues when the
Flask dashboard and the SSH server write simultaneously).
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional

import config


# ── Schema ─────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,               -- ISO 8601
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    username    TEXT    NOT NULL,
    password    TEXT    NOT NULL,
    success     INTEGER NOT NULL DEFAULT 0,     -- always 0 (we fake success)
    country     TEXT,
    country_code TEXT,
    city        TEXT,
    latitude    REAL,
    longitude   REAL,
    isp         TEXT,
    session_id  TEXT                            -- links to commands table
);

CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    session_id  TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    command     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attempts_ip        ON attempts(ip);
CREATE INDEX IF NOT EXISTS idx_attempts_timestamp ON attempts(timestamp);
CREATE INDEX IF NOT EXISTS idx_commands_session   ON commands(session_id);
"""


# ── Connection helper ──────────────────────────────────────────────────────────

@contextmanager
def _conn():
    """Context manager that opens a connection and commits/rolls back cleanly."""
    db = sqlite3.connect(str(config.DB_PATH))
    db.row_factory = sqlite3.Row   # rows behave like dicts
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create tables if they don't exist. Safe to call multiple times."""
    with _conn() as db:
        db.executescript(_SCHEMA)


# ── Write operations ───────────────────────────────────────────────────────────

def log_attempt(
    ip:          str,
    port:        int,
    username:    str,
    password:    str,
    session_id:  str,
    geo:         Optional[Dict] = None,
) -> int:
    """
    Record a login attempt. Returns the new row ID.
    geo dict is the response from geoip.lookup() — may be None if lookup failed.
    """
    now = datetime.now(timezone.utc).isoformat()
    geo = geo or {}

    with _conn() as db:
        cursor = db.execute(
            """
            INSERT INTO attempts
                (timestamp, ip, port, username, password,
                 country, country_code, city, latitude, longitude, isp, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now, ip, port, username, password,
                geo.get("country"),
                geo.get("countryCode"),
                geo.get("city"),
                geo.get("lat"),
                geo.get("lon"),
                geo.get("isp"),
                session_id,
            ),
        )
        return cursor.lastrowid


def log_command(session_id: str, ip: str, command: str) -> None:
    """Record a command typed during a fake interactive session."""
    with _conn() as db:
        db.execute(
            "INSERT INTO commands (timestamp, session_id, ip, command) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), session_id, ip, command),
        )


# ── Read operations (used by the dashboard API) ────────────────────────────────

def get_recent_attempts(limit: int = 100) -> List[Dict]:
    """Return the most recent login attempts, newest first."""
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM attempts ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_stats() -> Dict:
    """
    Aggregate statistics for the dashboard header cards.
    Returns a dict with total_attempts, unique_ips, unique_passwords,
    top_usernames, top_passwords, and attempts_per_hour (last 24h).
    """
    with _conn() as db:
        total = db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        unique_ips = db.execute("SELECT COUNT(DISTINCT ip) FROM attempts").fetchone()[0]
        unique_pwds = db.execute("SELECT COUNT(DISTINCT password) FROM attempts").fetchone()[0]

        top_usernames = db.execute(
            """SELECT username, COUNT(*) as count FROM attempts
               GROUP BY username ORDER BY count DESC LIMIT 10"""
        ).fetchall()

        top_passwords = db.execute(
            """SELECT password, COUNT(*) as count FROM attempts
               GROUP BY password ORDER BY count DESC LIMIT 10"""
        ).fetchall()

        top_countries = db.execute(
            """SELECT country, country_code, COUNT(*) as count FROM attempts
               WHERE country IS NOT NULL
               GROUP BY country ORDER BY count DESC LIMIT 10"""
        ).fetchall()

        # Attempts per hour for the last 24 hours
        hourly = db.execute(
            """SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                      COUNT(*) as count
               FROM attempts
               WHERE timestamp >= datetime('now', '-24 hours')
               GROUP BY hour
               ORDER BY hour ASC"""
        ).fetchall()

        total_commands = db.execute("SELECT COUNT(*) FROM commands").fetchone()[0]

        top_commands = db.execute(
            """SELECT command, COUNT(*) as count FROM commands
               GROUP BY command ORDER BY count DESC LIMIT 10"""
        ).fetchall()

    return {
        "total_attempts":  total,
        "unique_ips":      unique_ips,
        "unique_passwords": unique_pwds,
        "total_commands":  total_commands,
        "top_usernames":   [dict(r) for r in top_usernames],
        "top_passwords":   [dict(r) for r in top_passwords],
        "top_countries":   [dict(r) for r in top_countries],
        "hourly_attempts": [dict(r) for r in hourly],
    }


def get_recent_commands(limit: int = 50) -> List[Dict]:
    """Return the most recent commands captured, newest first."""
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM commands ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_attacker_profile(ip: str) -> Dict:
    """Return all data for a specific IP — used for the attacker detail view."""
    with _conn() as db:
        attempts = db.execute(
            "SELECT * FROM attempts WHERE ip = ? ORDER BY timestamp DESC",
            (ip,),
        ).fetchall()
        commands = db.execute(
            "SELECT * FROM commands WHERE ip = ? ORDER BY timestamp DESC",
            (ip,),
        ).fetchall()
    return {
        "ip":       ip,
        "attempts": [dict(r) for r in attempts],
        "commands": [dict(r) for r in commands],
    }
