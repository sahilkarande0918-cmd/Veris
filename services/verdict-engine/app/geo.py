"""Origin geolocation + anonymized-infrastructure flags [SIH26106 KC3].

Offline-first, like every external in Veris:
- Geolocation resolves from a bundled offline map (demo/seed IPs) so the forensic
  demo runs with the network off; online, `ip-api.com` (keyless, cached)
  supersedes it. Geolocation is enrichment -- it degrades, never blocks.
- TOR-exit / anonymized-infra detection is a bundled offline list.
- Every finding is a cited `Signal`; the verdict is still `rules.decide()`.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import httpx
from verdict import Signal

from .enrich import _cached, _store, is_offline

_GEO_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "geo"
_TIMEOUT = 6.0
_HOSTING_HINTS = ("hosting", "bulletproof", "cloud", "vps", "datacenter", "data center", "colo")


@lru_cache(maxsize=1)
def _offline_geo() -> dict:
    try:
        return json.loads((_GEO_DIR / "offline_geo.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


@lru_cache(maxsize=1)
def _tor_exits() -> frozenset[str]:
    try:
        lines = (_GEO_DIR / "tor_exits.txt").read_text(encoding="utf-8").splitlines()
    except OSError:
        return frozenset()
    return frozenset(x.strip() for x in lines if x.strip() and not x.startswith("#"))


def is_tor_exit(ip: str) -> bool:
    return ip in _tor_exits()


def geolocate(ip: str) -> dict:
    """Return {country, country_code, city, isp, org, asn} for an IP, or {}.

    Bundled offline map first (works offline), then cache, then ip-api online.
    """
    if not ip:
        return {}
    offline = _offline_geo().get(ip)
    if offline:
        return offline

    cache_key = f"geo_{ip}"
    cached = _cached(cache_key, ttl_hours=24 * 7)
    if cached is not None:
        return cached
    if is_offline():
        return {}

    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,as"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError):
        return {}
    if data.get("status") != "success":
        return {}
    geo = {
        "country": data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region": data.get("regionName", ""),
        "city": data.get("city", ""),
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
        "asn": data.get("as", ""),
    }
    _store(cache_key, geo)
    return geo


def geo_signals(ip: str, claims_india: bool) -> tuple[list[Signal], dict]:
    """Cited signals for the originating IP, plus the geo metadata for the UI."""
    geo = geolocate(ip)
    signals: list[Signal] = []
    if not ip:
        return signals, {}

    where = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x) or "unknown location"
    org = geo.get("org") or geo.get("isp") or "unknown network"
    signals.append(
        Signal(
            id="email_origin_geo",
            source="IP geolocation (ip-api / offline map)",
            value=f"originates from {where} via {org} {geo.get('asn', '')}".strip(),
            weight=0,
        )
    )

    if is_tor_exit(ip):
        signals.append(
            Signal(
                id="email_origin_tor",
                source="TOR exit-node list (offline)",
                value=f"{ip} is a known TOR exit node -- anonymized infrastructure",
                weight=30,
            )
        )
    elif any(h in f"{org} {geo.get('isp','')}".lower() for h in _HOSTING_HINTS):
        signals.append(
            Signal(
                id="email_origin_hosting",
                source="IP geolocation (network organization)",
                value=f"sent from hosting/cloud infrastructure ({org}), not a normal mail provider",
                weight=15,
            )
        )

    cc = geo.get("country_code", "")
    if claims_india and cc and cc != "IN":
        signals.append(
            Signal(
                id="email_origin_mismatch",
                source="origin-vs-claim geolocation",
                value=f"claims an Indian institution but originates from {geo.get('country', cc)}",
                weight=25,
            )
        )
    return signals, geo
