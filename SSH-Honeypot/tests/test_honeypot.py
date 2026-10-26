"""
tests/test_honeypot.py — Unit tests for the SSH honeypot.

Tests cover the database layer, geoip caching, and the fake shell
command response logic. The SSH server itself is not tested here
(integration test territory) but everything it depends on is.
"""

import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Database tests ─────────────────────────────────────────────────────────────

class TestDatabase:
    """Tests for honeypot/database.py using a temp database."""

    @pytest.fixture(autouse=True)
    def use_temp_db(self, tmp_path, monkeypatch):
        """Redirect DB_PATH to a fresh temp file for each test."""
        import config
        monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")

        from honeypot import database
        database.init_db()
        self.db = database

    def test_init_creates_tables(self):
        import config
        conn = sqlite3.connect(str(config.DB_PATH))
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        assert "attempts" in tables
        assert "commands" in tables

    def test_log_attempt_returns_id(self):
        row_id = self.db.log_attempt(
            ip="1.2.3.4", port=2222,
            username="root", password="123456",
            session_id="test-001",
            geo={"country": "China", "countryCode": "CN", "city": "Beijing",
                 "lat": 39.9, "lon": 116.4, "isp": "Alibaba"},
        )
        assert isinstance(row_id, int)
        assert row_id > 0

    def test_get_recent_attempts_newest_first(self):
        for i in range(3):
            self.db.log_attempt(
                ip=f"10.0.0.{i}", port=2222,
                username="admin", password=f"pass{i}",
                session_id=f"sess-{i}",
            )
        attempts = self.db.get_recent_attempts(limit=10)
        assert len(attempts) == 3
        # Newest first (highest ID first)
        assert attempts[0]["id"] > attempts[1]["id"]

    def test_log_command_and_retrieve(self):
        self.db.log_command("sess-001", "5.5.5.5", "id")
        self.db.log_command("sess-001", "5.5.5.5", "uname -a")
        commands = self.db.get_recent_commands(limit=10)
        assert len(commands) == 2
        cmds = [c["command"] for c in commands]
        assert "id" in cmds
        assert "uname -a" in cmds

    def test_get_stats_counts(self):
        self.db.log_attempt("1.1.1.1", 2222, "root", "123456", "s1")
        self.db.log_attempt("2.2.2.2", 2222, "admin", "password", "s2")
        self.db.log_attempt("1.1.1.1", 2222, "root", "password", "s3")  # same IP

        stats = self.db.get_stats()
        assert stats["total_attempts"] == 3
        assert stats["unique_ips"] == 2
        assert stats["unique_passwords"] == 2  # "123456" and "password"

    def test_get_attacker_profile(self):
        self.db.log_attempt("9.9.9.9", 2222, "root", "toor", "sess-99")
        self.db.log_command("sess-99", "9.9.9.9", "cat /etc/passwd")

        profile = self.db.get_attacker_profile("9.9.9.9")
        assert profile["ip"] == "9.9.9.9"
        assert len(profile["attempts"]) == 1
        assert len(profile["commands"]) == 1
        assert profile["commands"][0]["command"] == "cat /etc/passwd"

    def test_get_recent_attempts_respects_limit(self):
        for i in range(10):
            self.db.log_attempt(f"10.0.0.{i}", 2222, "root", f"p{i}", f"s{i}")
        assert len(self.db.get_recent_attempts(limit=5)) == 5

    def test_empty_db_stats_are_zero(self):
        stats = self.db.get_stats()
        assert stats["total_attempts"] == 0
        assert stats["unique_ips"] == 0


# ── GeoIP tests ────────────────────────────────────────────────────────────────

class TestGeoIP:
    """Tests for honeypot/geoip.py."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        from honeypot import geoip
        geoip._cache.clear()
        yield
        geoip._cache.clear()

    def test_private_ip_returns_private_network(self):
        from honeypot.geoip import lookup
        result = lookup("192.168.1.1")
        assert result is not None
        assert result["country"] == "Private Network"

    def test_loopback_ip_is_private(self):
        from honeypot.geoip import lookup
        result = lookup("127.0.0.1")
        assert result["country"] == "Private Network"

    def test_successful_api_lookup(self):
        from honeypot import geoip

        mock_response = {
            "status": "success",
            "country": "Germany", "countryCode": "DE",
            "city": "Berlin", "lat": 52.5, "lon": 13.4,
            "isp": "Hetzner",
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = lambda s: s
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = json.dumps(mock_response).encode()
            mock_urlopen.return_value = mock_ctx

            result = geoip.lookup("5.9.0.1")

        assert result["country"] == "Germany"
        assert result["countryCode"] == "DE"

    def test_cache_prevents_duplicate_requests(self):
        from honeypot import geoip

        mock_response = {
            "status": "success", "country": "France", "countryCode": "FR",
            "city": "Paris", "lat": 48.8, "lon": 2.3, "isp": "OVH",
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = lambda s: s
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = json.dumps(mock_response).encode()
            mock_urlopen.return_value = mock_ctx

            geoip.lookup("5.9.0.2")
            geoip.lookup("5.9.0.2")  # second call should use cache

        assert mock_urlopen.call_count == 1

    def test_api_failure_returns_none(self):
        from honeypot import geoip
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            result = geoip.lookup("5.9.0.3")

        assert result is None

    def test_disabled_geoip_returns_none(self):
        import config
        with patch.object(config, "GEOIP_ENABLED", False):
            from honeypot.geoip import lookup
            assert lookup("8.8.8.8") is None


# ── Fake shell response tests ──────────────────────────────────────────────────

class TestFakeShellResponses:
    """Tests for the fake shell via FakeFilesystem."""

    def test_id_returns_root(self):
        from honeypot.filesystem import FakeFilesystem
        out, _ = FakeFilesystem().handle_command("id")
        assert "uid=0(root)" in out

    def test_exit_ends_session(self):
        from honeypot.filesystem import FakeFilesystem
        _, is_exit = FakeFilesystem().handle_command("exit")
        assert is_exit is True

    def test_logout_ends_session(self):
        from honeypot.filesystem import FakeFilesystem
        _, is_exit = FakeFilesystem().handle_command("logout")
        assert is_exit is True

    def test_unknown_command_not_found(self):
        from honeypot.filesystem import FakeFilesystem
        out, is_exit = FakeFilesystem().handle_command("somefakecommand")
        assert "not found" in out
        assert is_exit is False
