"""
honeypot/threat_intel.py — TOR exit node and datacenter/VPN IP detection.

Enriches attacker profiles with anonymization context:
  - TOR exit nodes: attackers hiding their real IP via the TOR network
  - Datacenter ASNs: cloud/VPS providers commonly used to launch attacks
    (DigitalOcean, Linode, OVH, Vultr, etc.)

No API keys needed — uses public data sources:
  - TOR exit list: https://check.torproject.org/torbulkexitlist (plain text)
  - ASN classification: based on known datacenter ASN prefixes and the
    ISP/org fields returned by ip-api.com geolocation

Offensive context:
  TOR and datacenter IPs are how attackers maintain operational security
  during a campaign. Correlating attack patterns across these IPs tells
  you if multiple "different" attackers are actually the same campaign.
  This is exactly the kind of enrichment a real SOC does with a SIEM.

Data is cached in memory and refreshed every CACHE_TTL seconds.
On startup, the TOR list is fetched once in the background so it doesn't
delay the first connection.
"""

import ipaddress
import logging
import threading
import time
import urllib.request
from typing import Dict, Optional, Set

log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

TOR_LIST_URL    = "https://check.torproject.org/torbulkexitlist"
TOR_CACHE_TTL   = 3600        # refresh TOR list every hour
FETCH_TIMEOUT   = 10          # seconds for HTTP requests

# Known datacenter/hosting provider keywords in ISP/org fields.
# These are companies commonly used to launch attacks via rented VPS.
DATACENTER_KEYWORDS = {
    "digitalocean", "linode", "vultr", "ovh", "hetzner", "scaleway",
    "amazon", "aws", "google cloud", "microsoft azure", "alibaba",
    "choopa", "psychz", "tzulo", "quadranet", "serverius",
    "frantech", "buyvm", "hostkey", "m247", "combahton",
    "datacamp", "wholesale internet", "serverius", "nexeon",
    "incapsula", "cloudflare",   # CDN/proxy
}


# ── Cache ──────────────────────────────────────────────────────────────────────

class _TorCache:
    def __init__(self):
        self._ips:      Set[str] = set()
        self._lock:     threading.Lock = threading.Lock()
        self._fetched_at: float = 0.0
        self._ready:    bool = False

    def refresh_if_stale(self) -> None:
        """Fetch TOR exit list if cache is empty or expired. Non-blocking."""
        if time.time() - self._fetched_at < TOR_CACHE_TTL:
            return
        thread = threading.Thread(target=self._fetch, daemon=True)
        thread.start()

    def _fetch(self) -> None:
        try:
            req = urllib.request.Request(
                TOR_LIST_URL,
                headers={"User-Agent": "ssh-honeypot/1.0 (threat-intel)"},
            )
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                text = resp.read().decode("utf-8", errors="replace")

            new_ips = {
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.startswith("#")
            }

            with self._lock:
                self._ips        = new_ips
                self._fetched_at = time.time()
                self._ready      = True

            log.info("TOR exit list updated: %d nodes", len(new_ips))

        except Exception as e:
            log.debug("Could not fetch TOR exit list: %s", e)
            with self._lock:
                self._ready = True    # mark ready even on failure

    def is_tor(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._ready

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._ips)


_tor_cache = _TorCache()


def bootstrap() -> None:
    """
    Pre-fetch TOR list in the background at startup.
    Call once from main.py after logging is set up.
    """
    log.info("Fetching TOR exit node list in background...")
    _tor_cache._fetch()


# ── Public API ─────────────────────────────────────────────────────────────────

def enrich(ip: str, geo: Optional[Dict] = None) -> Dict:
    """
    Return threat intelligence context for an IP address.

    Args:
        ip:  the attacker IP string
        geo: optional geolocation dict from geoip.lookup() — used to
             check ISP/org for datacenter keywords

    Returns dict with keys:
        is_tor        : bool
        is_datacenter : bool
        is_proxy      : bool  (detected via ISP field)
        tags          : list of string tags, e.g. ["tor", "datacenter:digitalocean"]
        risk_level    : "high" | "medium" | "low"
    """
    _tor_cache.refresh_if_stale()

    is_tor        = _tor_cache.is_tor(ip)
    is_datacenter = False
    is_proxy      = False
    dc_name       = None
    tags          = []

    # Check ISP/org fields from geolocation
    if geo:
        isp = (geo.get("isp") or "").lower()
        org = (geo.get("org") or "").lower()
        combined = isp + " " + org

        for keyword in DATACENTER_KEYWORDS:
            if keyword in combined:
                is_datacenter = True
                dc_name = keyword
                break

        # Proxy/VPN indicators in org name
        proxy_keywords = {"vpn", "proxy", "anonymize", "anonymous", "hide", "privacy"}
        if any(kw in combined for kw in proxy_keywords):
            is_proxy = True

    # Build tags
    if is_tor:
        tags.append("tor")
    if is_datacenter and dc_name:
        tags.append(f"datacenter:{dc_name}")
    if is_proxy:
        tags.append("proxy")

    # Risk level
    if is_tor:
        risk = "high"
    elif is_datacenter or is_proxy:
        risk = "medium"
    else:
        risk = "low"

    return {
        "is_tor":        is_tor,
        "is_datacenter": is_datacenter,
        "is_proxy":      is_proxy,
        "dc_name":       dc_name,
        "tags":          tags,
        "risk_level":    risk,
    }


def is_tor_exit(ip: str) -> bool:
    """Quick check — is this IP a known TOR exit node?"""
    _tor_cache.refresh_if_stale()
    return _tor_cache.is_tor(ip)


def tor_node_count() -> int:
    """How many TOR exit nodes are in the current cache."""
    return _tor_cache.count
