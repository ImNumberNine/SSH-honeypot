"""
tests/test_features.py — Tests for detector, threat_intel, and report modules.
"""

import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ═══════════════════════════════════════════════════════════════════════════════
# BOT VS HUMAN DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestBehaviorDetector:
    """Tests for honeypot/detector.py"""

    @pytest.fixture
    def det(self):
        from honeypot.detector import BehaviorDetector
        return BehaviorDetector()

    @pytest.fixture
    def profile(self, det):
        return det.new_profile("test-001", "1.2.3.4")

    def test_new_profile_starts_unknown(self, det, profile):
        from honeypot.detector import SessionType
        assert profile.classification == SessionType.UNKNOWN

    def test_bot_detected_from_large_chunks(self, det, profile):
        """Bot sends entire commands at once — large recv() chunks."""
        from honeypot.detector import SessionType
        for i in range(8):
            det.record_keystrokes(profile, b"cat /etc/passwd\r", time.monotonic())
        det.classify(profile)
        assert profile.classification in (SessionType.BOT, SessionType.LIKELY_BOT)
        assert any("large_chunks" in s for s in profile.signals)

    def test_human_detected_from_char_by_char(self, det, profile):
        """Human types one character at a time with variable delays."""
        from honeypot.detector import SessionType
        import random
        ts = time.monotonic()
        for char in "ls -la\r":
            ts += random.uniform(0.08, 0.35)   # 80-350ms between chars
            det.record_keystrokes(profile, char.encode(), ts)
        det.classify(profile)
        # With realistic human delays, should not be classified as bot
        assert profile.classification != SessionType.BOT

    def test_bot_detected_from_high_attempt_count(self, det, profile):
        from honeypot.detector import SessionType
        for i in range(15):
            det.record_auth_attempt(profile, "root", f"password{i}")
        det.classify(profile)
        assert profile.classification in (SessionType.BOT, SessionType.LIKELY_BOT)
        assert any("high_attempt_count" in s for s in profile.signals)

    def test_wordlist_pattern_detected(self, det):
        from honeypot.detector import BehaviorDetector
        passwords = ["password", "123456", "admin", "root", "test", "letmein"]
        assert BehaviorDetector._looks_like_wordlist(passwords) is True

    def test_non_wordlist_not_flagged(self, det):
        from honeypot.detector import BehaviorDetector
        passwords = ["Tr0ub4d0r&3", "c0rr3ct-h0rs3", "b4tt3ry-staple", "X9#mK2@"]
        assert BehaviorDetector._looks_like_wordlist(passwords) is False

    def test_sequential_suffix_detected(self, det):
        from honeypot.detector import BehaviorDetector
        passwords = ["pass1", "pass2", "pass3", "pass4", "pass5"]
        assert BehaviorDetector._looks_like_wordlist(passwords) is True

    def test_unknown_with_insufficient_data(self, det, profile):
        from honeypot.detector import SessionType
        # Only one event — not enough to classify
        det.record_keystrokes(profile, b"i", time.monotonic())
        det.classify(profile)
        assert profile.classification == SessionType.UNKNOWN

    def test_confidence_between_0_and_1(self, det, profile):
        for i in range(10):
            det.record_auth_attempt(profile, "admin", f"pass{i}")
        det.classify(profile)
        assert 0.0 <= profile.confidence <= 1.0

    def test_record_command_tracked(self, det, profile):
        det.record_command(profile, "id")
        det.record_command(profile, "whoami")
        assert len(profile.commands) == 2

    def test_repetitive_commands_flagged(self, det, profile):
        for _ in range(6):
            det.record_command(profile, "id")
        det.classify(profile)
        assert any("repetitive" in s for s in profile.signals)


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatIntel:
    """Tests for honeypot/threat_intel.py"""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        from honeypot import threat_intel
        threat_intel._tor_cache._ips = set()
        threat_intel._tor_cache._fetched_at = 0.0
        yield
        threat_intel._tor_cache._ips = set()

    def test_enrich_returns_dict_with_required_keys(self):
        from honeypot.threat_intel import enrich
        result = enrich("1.2.3.4", {})
        assert "is_tor" in result
        assert "is_datacenter" in result
        assert "risk_level" in result
        assert "tags" in result

    def test_tor_ip_detected(self):
        from honeypot import threat_intel
        threat_intel._tor_cache._ips = {"5.9.0.1"}
        threat_intel._tor_cache._fetched_at = float("inf")

        result = threat_intel.enrich("5.9.0.1")
        assert result["is_tor"] is True
        assert result["risk_level"] == "high"
        assert "tor" in result["tags"]

    def test_non_tor_ip_not_flagged(self):
        from honeypot.threat_intel import enrich
        result = enrich("8.8.8.8", {"isp": "Google LLC", "org": "Google"})
        assert result["is_tor"] is False

    def test_digitalocean_flagged_as_datacenter(self):
        from honeypot.threat_intel import enrich
        geo = {"isp": "DigitalOcean LLC", "org": "DigitalOcean"}
        result = enrich("192.0.2.1", geo)
        assert result["is_datacenter"] is True
        assert result["risk_level"] == "medium"
        assert any("datacenter" in t for t in result["tags"])

    def test_residential_isp_not_datacenter(self):
        from honeypot.threat_intel import enrich
        geo = {"isp": "Comcast Cable", "org": "Comcast"}
        result = enrich("100.0.0.1", geo)
        assert result["is_datacenter"] is False
        assert result["risk_level"] == "low"

    def test_vpn_isp_flagged_as_proxy(self):
        from honeypot.threat_intel import enrich
        geo = {"isp": "NordVPN Anonymous Services", "org": "Private VPN"}
        result = enrich("203.0.113.1", geo)
        assert result["is_proxy"] is True

    def test_empty_geo_does_not_crash(self):
        from honeypot.threat_intel import enrich
        result = enrich("1.2.3.4", None)
        assert isinstance(result, dict)

    def test_is_tor_exit_convenience_function(self):
        from honeypot import threat_intel
        threat_intel._tor_cache._ips = {"10.0.0.1"}
        threat_intel._tor_cache._fetched_at = float("inf")
        assert threat_intel.is_tor_exit("10.0.0.1") is True
        assert threat_intel.is_tor_exit("10.0.0.2") is False

    def test_tor_node_count(self):
        from honeypot import threat_intel
        threat_intel._tor_cache._ips = {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
        assert threat_intel.tor_node_count() == 3

    def test_tor_tags_include_tor(self):
        from honeypot import threat_intel
        threat_intel._tor_cache._ips = {"5.5.5.5"}
        threat_intel._tor_cache._fetched_at = float("inf")
        result = threat_intel.enrich("5.5.5.5")
        assert "tor" in result["tags"]


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportGenerator:
    """Tests for honeypot/report.py"""

    @pytest.fixture(autouse=True)
    def use_temp_db(self, tmp_path, monkeypatch):
        import config
        monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
        from honeypot import database
        database.init_db()

        # Seed some test data
        database.log_attempt("1.1.1.1", 2222, "root",  "123456",   "s1",
                             {"country": "China", "countryCode": "CN",
                              "city": "Beijing", "lat": 39.9, "lon": 116.4, "isp": "Alibaba"})
        database.log_attempt("2.2.2.2", 2222, "admin", "password", "s2",
                             {"country": "Russia", "countryCode": "RU",
                              "city": "Moscow",  "lat": 55.7, "lon": 37.6, "isp": "Rostelecom"})
        database.log_attempt("1.1.1.1", 2222, "root",  "toor",     "s3")
        database.log_command("s1", "1.1.1.1", "id")
        database.log_command("s1", "1.1.1.1", "[DECOY] /root/.env")

    def test_generate_returns_html_string(self):
        from honeypot.report import generate
        html = generate(days=7)
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html

    def test_report_contains_key_sections(self):
        from honeypot.report import generate
        html = generate(days=7)
        assert "Top credential pairs"  in html
        assert "Most active source IPs" in html
        assert "Top source countries"  in html
        assert "Post-auth commands"    in html

    def test_report_shows_attempt_counts(self):
        from honeypot.report import generate
        html = generate(days=7)
        # 3 total attempts were seeded
        assert "3" in html

    def test_report_includes_country_data(self):
        from honeypot.report import generate
        html = generate(days=7)
        assert "China" in html or "Russia" in html

    def test_report_highlights_decoy_reads(self):
        from honeypot.report import generate
        html = generate(days=7)
        assert "DECOY" in html

    def test_report_saved_to_file(self, tmp_path):
        from honeypot.report import generate
        output = str(tmp_path / "test-report.html")
        generate(days=7, output_path=output)
        assert Path(output).exists()
        content = Path(output).read_text()
        assert "<!DOCTYPE html>" in content

    def test_hourly_heatmap_svg_generated(self):
        from honeypot.report import _hourly_heatmap_svg
        svg = _hourly_heatmap_svg([0] * 24)
        assert "<svg" in svg
        assert "<rect" in svg

    def test_heatmap_handles_zero_counts(self):
        from honeypot.report import _hourly_heatmap_svg
        svg = _hourly_heatmap_svg([0] * 24)
        assert "NaN" not in svg

    def test_heatmap_handles_high_counts(self):
        from honeypot.report import _hourly_heatmap_svg
        counts = [0] * 24
        counts[3] = 1000
        counts[14] = 500
        svg = _hourly_heatmap_svg(counts)
        assert "#f85149" in svg   # red for peak hour

    def test_fetch_report_data_empty_db(self, tmp_path, monkeypatch):
        """A fresh empty DB should return zeros without crashing."""
        import config
        fresh_db = tmp_path / "fresh.db"
        monkeypatch.setattr(config, "DB_PATH", fresh_db)
        from honeypot import database as db2
        db2.init_db()
        from honeypot.report import _fetch_report_data
        data = _fetch_report_data(days=7)
        assert data["total_attempts"] == 0
        assert data["unique_ips"] == 0
        assert len(data["hourly_counts"]) == 24
