"""
honeypot/geoip.py — IP geolocation using ip-api.com (free, no API key).

We cache results in memory to avoid hammering the API when the same IP
makes multiple attempts (which is extremely common with botnet activity).
The cache is a simple dict with TTL — good enough for a honeypot.

Rate limit: ip-api.com free tier allows 45 requests/minute.
Private/reserved IPs are returned as "Private Network" without an API call.
"""

import ipaddress
import logging
import time
from typing import Dict, Optional

import urllib.request
import urllib.error
import json

import config

logger = logging.getLogger(__name__)

# ── In-memory cache ────────────────────────────────────────────────────────────
# Structure: { ip: (timestamp, geo_dict) }
_cache: Dict[str, tuple] = {}


def _is_private(ip: str) -> bool:
    """Return True if the IP is a private/loopback/reserved address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup(ip: str) -> Optional[Dict]:
    """
    Geolocate an IP address.

    Returns a dict with keys: country, countryCode, city, lat, lon, isp, org.
    Returns None if geolocation is disabled, the lookup fails, or the IP
    is a private address.

    Results are cached for GEOIP_CACHE_TTL seconds to avoid repeated API calls
    from the same attacker IP (botnets hammer the same credentials repeatedly).
    """
    if not config.GEOIP_ENABLED:
        return None

    if _is_private(ip):
        return {
            "country":     "Private Network",
            "countryCode": "XX",
            "city":        "Local",
            "lat":         0.0,
            "lon":         0.0,
            "isp":         "Private",
        }

    # Check cache
    if ip in _cache:
        cached_at, cached_data = _cache[ip]
        if time.time() - cached_at < config.GEOIP_CACHE_TTL:
            return cached_data

    # Fetch from ip-api.com
    url = config.GEOIP_URL.format(ip=ip)
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ssh-honeypot/1.0"},
        )
        with urllib.request.urlopen(req, timeout=config.GEOIP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") != "success":
            logger.debug("GeoIP lookup failed for %s: %s", ip, data.get("message"))
            return None

        result = {
            "country":     data.get("country"),
            "countryCode": data.get("countryCode"),
            "city":        data.get("city"),
            "lat":         data.get("lat"),
            "lon":         data.get("lon"),
            "isp":         data.get("isp"),
        }

        _cache[ip] = (time.time(), result)
        return result

    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        logger.debug("GeoIP request error for %s: %s", ip, e)
        return None
