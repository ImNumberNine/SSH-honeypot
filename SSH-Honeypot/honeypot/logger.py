"""
honeypot/logger.py — Structured event logging to JSONL.

Every event (attempt, command, session_start, session_end) is written as
a single JSON object per line to data/events.jsonl. This format is:
  - Easy to grep and parse with jq
  - Compatible with log shippers (Filebeat, Fluentd, Vector)
  - The input format for the siem-lite-dashboard project in the roadmap

Standard Python logging (to console/file) is also configured here so
the server prints human-readable output while running.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import config


# ── Console / file logger setup ───────────────────────────────────────────────

def setup_logging() -> None:
    """
    Configure the root logger.
    INFO+ to console (with color if terminal supports it).
    DEBUG+ to data/honeypot.log.
    """
    fmt = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
    datefmt = "%H:%M:%S"

    handlers = [logging.StreamHandler(sys.stdout)]

    log_file = config.DATA_DIR / "honeypot.log"
    handlers.append(logging.FileHandler(str(log_file)))

    logging.basicConfig(
        level   = getattr(logging, config.LOG_LEVEL),
        format  = fmt,
        datefmt = datefmt,
        handlers = handlers,
    )

    # Suppress paramiko's verbose transport debug messages
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("paramiko.transport").setLevel(logging.ERROR)


# ── JSONL structured event writer ─────────────────────────────────────────────

_jsonl_logger = logging.getLogger("honeypot.events")


def _write_event(event_type: str, payload: Dict[str, Any]) -> None:
    """
    Append a structured event to data/events.jsonl.
    Each line is a self-contained JSON object with a type and timestamp.
    """
    event = {
        "type":      event_type,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        **payload,
    }
    try:
        with open(config.LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        _jsonl_logger.error("Failed to write event log: %s", e)


# ── Public event functions ─────────────────────────────────────────────────────

def log_attempt(ip: str, port: int, username: str, password: str,
                session_id: str, geo: Dict = None) -> None:
    """Log a credential attempt event."""
    logger = logging.getLogger("honeypot.attempt")
    geo    = geo or {}

    logger.info(
        "ATTEMPT  %s  user=%-16s  pass=%-20s  [%s, %s]",
        ip, username, password,
        geo.get("country", "?"), geo.get("city", "?"),
    )

    _write_event("attempt", {
        "session_id": session_id,
        "ip":         ip,
        "port":       port,
        "username":   username,
        "password":   password,
        "geo":        geo,
    })


def log_command(session_id: str, ip: str, command: str) -> None:
    """Log a command captured during a fake interactive session."""
    logger = logging.getLogger("honeypot.command")
    logger.info("COMMAND  %s  $ %s", ip, command)

    _write_event("command", {
        "session_id": session_id,
        "ip":         ip,
        "command":    command,
    })


def log_session_start(session_id: str, ip: str, port: int) -> None:
    logger = logging.getLogger("honeypot.session")
    logger.info("SESSION_START  %s:%d  id=%s", ip, port, session_id)
    _write_event("session_start", {
        "session_id": session_id,
        "ip":         ip,
        "port":       port,
    })


def log_session_end(session_id: str, ip: str, duration: float) -> None:
    logger = logging.getLogger("honeypot.session")
    logger.info("SESSION_END  %s  id=%s  duration=%.1fs", ip, session_id, duration)
    _write_event("session_end", {
        "session_id": session_id,
        "ip":         ip,
        "duration_s": round(duration, 2),
    })
