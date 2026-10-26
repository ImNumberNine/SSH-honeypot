"""
honeypot/detector.py — Bot vs human detection based on behavioral analysis.

Bots and automated scripts have fundamentally different timing patterns than
humans. This module analyzes two signals to classify each session:

1. KEYSTROKE TIMING — Humans type with variable inter-key delays (50-400ms)
   with natural pauses at word/sentence boundaries. Bots submit complete
   command strings instantly (< 5ms between characters) or at perfectly
   uniform intervals — a statistical impossibility for human typing.

2. CREDENTIAL PATTERN — Bots cycle through wordlists sequentially and try
   many credentials fast. Humans try a small number of meaningful guesses.

Why this matters for threat intelligence:
  A human attacker actively working a target is far more interesting than
  a botnet spray. Classifying sessions lets us prioritize which ones to
  study and can trigger higher-priority alerts in a SIEM integration.

Offensive context (HTB/pentest relevance):
  Understanding how detection works helps you evade it. A real attacker
  mimicking human timing (random delays, natural pauses) would defeat
  simple timing-based detection — which is exactly why modern IDS systems
  use multiple signals rather than a single threshold.
"""

import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class SessionType(str, Enum):
    """Classification result for a session."""
    HUMAN      = "human"       # Almost certainly a human attacker
    BOT        = "bot"         # Automated script or botnet node
    LIKELY_BOT = "likely_bot"  # Automated but not 100% certain
    UNKNOWN    = "unknown"     # Not enough data to classify


@dataclass
class TimingEvent:
    """A single keystroke or character receive event."""
    timestamp:  float    # time.monotonic() at receipt
    char_count: int      # number of characters in this chunk


@dataclass
class SessionProfile:
    """
    Behavioral profile built up over the course of a session.
    Updated incrementally as events arrive — no need to store full history.
    """
    session_id:        str
    ip:                str

    # Keystroke timing
    timing_events:     List[TimingEvent] = field(default_factory=list)
    inter_key_delays:  List[float]       = field(default_factory=list)  # ms

    # Command-level signals
    commands:          List[str]         = field(default_factory=list)
    command_timestamps: List[float]      = field(default_factory=list)

    # Auth signals
    auth_attempts:     int               = 0
    auth_usernames:    List[str]         = field(default_factory=list)
    auth_passwords:    List[str]         = field(default_factory=list)
    first_seen:        float             = field(default_factory=time.monotonic)

    # Result
    classification:    SessionType       = SessionType.UNKNOWN
    confidence:        float             = 0.0    # 0.0 - 1.0
    signals:           List[str]         = field(default_factory=list)


class BehaviorDetector:
    """
    Analyzes session behavior and classifies it as human or automated.

    Usage:
        profile = BehaviorDetector.new_profile(session_id, ip)
        detector.record_keystrokes(profile, data, timestamp)
        detector.record_command(profile, command)
        result = detector.classify(profile)
    """

    # ── Thresholds ─────────────────────────────────────────────────────
    # Humans rarely type faster than ~15 chars/sec (67ms between chars)
    # at sustained speed. Bots submit full strings in a single chunk.
    BOT_CHUNK_THRESHOLD   = 4     # chars in one recv() chunk = bot signal
    MIN_HUMAN_DELAY_MS    = 30    # below this = bot timing
    MAX_BOT_DELAY_CV      = 0.15  # coefficient of variation — bots are uniform

    # Bots try many passwords quickly; humans try a few meaningful ones
    BOT_ATTEMPT_THRESHOLD = 8     # more than this in a session = likely bot
    BOT_ATTEMPT_RATE      = 3.0   # attempts per second = bot (sustained)

    # Minimum events before we make a confident classification
    MIN_EVENTS_FOR_TIMING = 5
    MIN_COMMANDS_FOR_CLASS = 3

    @staticmethod
    def new_profile(session_id: str, ip: str) -> SessionProfile:
        return SessionProfile(session_id=session_id, ip=ip)

    def record_keystrokes(
        self,
        profile: SessionProfile,
        data: bytes,
        timestamp: Optional[float] = None,
    ) -> None:
        """
        Record a chunk of data received from the client.

        Called by the handler for every recv() call. The timestamp is the
        moment the data arrived — inter-chunk delay is the key signal.
        """
        ts = timestamp or time.monotonic()
        char_count = len(data)

        event = TimingEvent(timestamp=ts, char_count=char_count)
        profile.timing_events.append(event)

        # Compute inter-key delay from the previous event
        if len(profile.timing_events) >= 2:
            prev = profile.timing_events[-2]
            delay_ms = (ts - prev.timestamp) * 1000
            profile.inter_key_delays.append(delay_ms)

    def record_command(self, profile: SessionProfile, command: str) -> None:
        """Record a completed command with its timestamp."""
        profile.commands.append(command)
        profile.command_timestamps.append(time.monotonic())

    def record_auth_attempt(
        self, profile: SessionProfile, username: str, password: str
    ) -> None:
        """Record a credential attempt."""
        profile.auth_attempts += 1
        profile.auth_usernames.append(username)
        profile.auth_passwords.append(password)

    def classify(self, profile: SessionProfile) -> SessionProfile:
        """
        Classify the session based on accumulated behavioral signals.
        Updates profile.classification, profile.confidence, and profile.signals.
        Returns the updated profile.
        """
        bot_score   = 0.0
        human_score = 0.0
        signals     = []

        # ── Signal 1: Keystroke chunk size ────────────────────────────
        # Bots send entire commands at once (large chunks).
        # Humans send one character at a time (chunk_count ≈ 1 per event).
        if profile.timing_events:
            large_chunks = sum(
                1 for e in profile.timing_events
                if e.char_count >= self.BOT_CHUNK_THRESHOLD
            )
            chunk_ratio = large_chunks / len(profile.timing_events)

            if chunk_ratio > 0.7:
                bot_score += 2.5
                signals.append(f"large_chunks:{chunk_ratio:.0%}")
            elif chunk_ratio < 0.1 and len(profile.timing_events) > 5:
                human_score += 1.5
                signals.append("char_by_char_typing")

        # ── Signal 2: Keystroke timing uniformity ─────────────────────
        # Coefficient of variation (CV) = stddev / mean.
        # Humans: CV > 0.5 (highly variable timing).
        # Bots:   CV < 0.15 (mechanically uniform).
        if len(profile.inter_key_delays) >= self.MIN_EVENTS_FOR_TIMING:
            delays = profile.inter_key_delays
            mean   = statistics.mean(delays)
            stddev = statistics.stdev(delays) if len(delays) > 1 else 0

            if mean > 0:
                cv = stddev / mean
                if cv < self.MAX_BOT_DELAY_CV:
                    bot_score += 2.0
                    signals.append(f"uniform_timing:cv={cv:.2f}")
                elif cv > 0.6:
                    human_score += 1.5
                    signals.append(f"variable_timing:cv={cv:.2f}")

            # Very fast average typing speed = bot
            if mean < self.MIN_HUMAN_DELAY_MS:
                bot_score += 2.0
                signals.append(f"fast_typing:{mean:.0f}ms_avg")

        # ── Signal 3: Auth attempt volume ─────────────────────────────
        if profile.auth_attempts >= self.BOT_ATTEMPT_THRESHOLD:
            bot_score += 2.0
            signals.append(f"high_attempt_count:{profile.auth_attempts}")

        # ── Signal 4: Auth attempt rate ───────────────────────────────
        elapsed = time.monotonic() - profile.first_seen
        if elapsed > 0 and profile.auth_attempts >= 3:
            rate = profile.auth_attempts / elapsed
            if rate >= self.BOT_ATTEMPT_RATE:
                bot_score += 1.5
                signals.append(f"high_attempt_rate:{rate:.1f}/s")

        # ── Signal 5: Sequential wordlist pattern ─────────────────────
        # Bots iterate wordlists in predictable order.
        # Detect by checking if passwords are all from a common list
        # or have obviously sequential patterns (pass1, pass2, pass3).
        if len(profile.auth_passwords) >= 4:
            if self._looks_like_wordlist(profile.auth_passwords):
                bot_score += 1.5
                signals.append("wordlist_pattern")

        # ── Signal 6: Command diversity ───────────────────────────────
        # Humans explore interactively; bots run a fixed script.
        if len(profile.commands) >= self.MIN_COMMANDS_FOR_CLASS:
            unique_ratio = len(set(profile.commands)) / len(profile.commands)
            if unique_ratio < 0.5:
                bot_score += 1.0
                signals.append(f"repetitive_commands:{unique_ratio:.0%}_unique")

        # ── Classification ─────────────────────────────────────────────
        total = bot_score + human_score
        if total < 1.0:
            profile.classification = SessionType.UNKNOWN
            profile.confidence     = 0.0
        elif bot_score > human_score * 2:
            profile.classification = SessionType.BOT
            profile.confidence     = min(bot_score / (total + 1), 0.99)
        elif bot_score > human_score:
            profile.classification = SessionType.LIKELY_BOT
            profile.confidence     = min(bot_score / (total + 1), 0.85)
        else:
            profile.classification = SessionType.HUMAN
            profile.confidence     = min(human_score / (total + 1), 0.90)

        profile.signals = signals
        return profile

    @staticmethod
    def _looks_like_wordlist(passwords: List[str]) -> bool:
        """
        Heuristic: detect sequential or dictionary-like password patterns.
        Returns True if the list looks like it came from a wordlist.
        """
        # Common wordlist passwords
        common = {
            "password", "123456", "admin", "root", "test", "guest",
            "letmein", "welcome", "monkey", "dragon", "master", "pass",
            "qwerty", "abc123", "password1", "1234567", "12345678",
        }
        common_hits = sum(1 for p in passwords if p.lower() in common)
        if common_hits / len(passwords) >= 0.5:
            return True

        # Sequential numeric suffix pattern: pass1, pass2, pass3
        import re
        numeric_suffixes = [re.sub(r'\d+$', '', p) for p in passwords]
        if len(set(numeric_suffixes)) == 1 and numeric_suffixes[0]:
            return True

        return False


# Module-level singleton — shared across all sessions
detector = BehaviorDetector()
