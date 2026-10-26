"""
config.py — Centralized configuration for the SSH honeypot.

All tuneable parameters live here. In production you'd override these
via environment variables or a .env file — never hardcode in the modules.
"""

import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR  = Path(__file__).parent
DATA_DIR  = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH   = DATA_DIR / "honeypot.db"
LOG_PATH  = DATA_DIR / "events.jsonl"    # structured log, one JSON per line
KEY_PATH  = DATA_DIR / "server.key"      # RSA host key (auto-generated)

# ── SSH server ─────────────────────────────────────────────────────────────────

SSH_HOST        = os.getenv("SSH_HOST", "0.0.0.0")
SSH_PORT        = int(os.getenv("SSH_PORT", "2222"))   # 22 requires root; 2222 is safer for dev
SSH_BANNER      = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
SSH_MAX_WORKERS = int(os.getenv("SSH_MAX_WORKERS", "50"))

# How long to keep a fake session open before disconnecting the attacker.
# Longer = more commands captured, but more resource use.
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "30"))  # seconds

# Fake prompt shown to attackers after "successful" login.
FAKE_PROMPT     = os.getenv("FAKE_PROMPT", "root@ubuntu:~# ")

# ── Dashboard ──────────────────────────────────────────────────────────────────

DASHBOARD_HOST  = os.getenv("DASHBOARD_HOST", "127.0.0.1")  # localhost only by default
DASHBOARD_PORT  = int(os.getenv("DASHBOARD_PORT", "8080"))
DASHBOARD_DEBUG = os.getenv("DASHBOARD_DEBUG", "false").lower() == "true"

# Secret key for Flask sessions (change this in production)
FLASK_SECRET    = os.getenv("FLASK_SECRET", "change-me-in-production")

# ── GeoIP ──────────────────────────────────────────────────────────────────────

# ip-api.com free tier: 45 requests/minute, no API key needed.
# Set to False to disable geolocation (useful in air-gapped environments).
GEOIP_ENABLED   = os.getenv("GEOIP_ENABLED", "true").lower() == "true"
GEOIP_URL       = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org"
GEOIP_TIMEOUT   = int(os.getenv("GEOIP_TIMEOUT", "5"))  # seconds
GEOIP_CACHE_TTL = int(os.getenv("GEOIP_CACHE_TTL", "3600"))  # 1 hour in-memory cache

# ── Logging ────────────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
