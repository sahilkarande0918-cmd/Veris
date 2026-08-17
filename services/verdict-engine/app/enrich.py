"""Network enrichment: Safe Browsing, VirusTotal, RDAP, TLS certificate.

Three rules govern everything in this file:

1. **Enrichment, never dependency.** Every function returns `[]` on any
   failure. A dead network, a missing key, or a rate limit degrades the
   evidence, never the availability of a verdict.
2. **Offline means offline.** `VERIS_OFFLINE=1` short-circuits the lot.
3. **Cache the rate-limited ones.** VirusTotal's free tier is ~4 req/min.
"""

import json
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from verdict import Signal

CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / ".cache"
_TIMEOUT = 6.0


def is_offline() -> bool:
    return os.getenv("VERIS_OFFLINE", "0") == "1"


def _cache_path(key: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in key)[:120]
    return CACHE_DIR / f"{safe}.json"


def _cached(key: str, ttl_hours: float):
    path = _cache_path(key)
    if not path.exists():
        return None
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if time.time() - blob.get("stored_at", 0) > ttl_hours * 3600:
        return None
    return blob.get("payload")


def _store(key: str, payload) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(key).write_text(
            json.dumps({"stored_at": time.time(), "payload": payload}),
            encoding="utf-8",
        )
    except OSError:
        pass  # a broken cache must never break a verdict


def safe_browsing(url: str) -> list[Signal]:
    """Google Safe Browsing v4 threatMatches:find.

    Attribution required wherever this is shown: "Advisory provided by Google".
    """
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key or is_offline():
        return []

    cache_key = f"gsb_{url}"
    matches = _cached(cache_key, ttl_hours=12)
    if matches is None:
        body = {
            "client": {"clientId": "veris", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            response = httpx.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": key},
                json=body,
                timeout=_TIMEOUT,
            )
            response.raise_for_status()
            matches = response.json().get("matches", [])
        except (httpx.HTTPError, json.JSONDecodeError):
            return []
        _store(cache_key, matches)

    if not matches:
        return []
    threat = matches[0].get("threatType", "THREAT")
    return [
        Signal(
            id="safe_browsing_hit",
            source="Google Safe Browsing v4 (Advisory provided by Google)",
            value=f"listed as {threat}",
            weight=80,
        )
    ]


def virustotal(domain: str) -> list[Signal]:
    """VirusTotal v3 domain report: detection ratio, registrar, creation date.

    Cached for 24h by default -- the free tier allows only ~4 requests/min.
    """
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key or is_offline():
        return []

    ttl = float(os.getenv("VIRUSTOTAL_CACHE_TTL_HOURS", "24"))
    cache_key = f"vt_{domain}"
    attributes = _cached(cache_key, ttl_hours=ttl)
    if attributes is None:
        try:
            response = httpx.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": key},
                timeout=_TIMEOUT,
            )
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
        except (httpx.HTTPError, KeyError, json.JSONDecodeError):
            return []
        _store(cache_key, attributes)

    signals: list[Signal] = []
    stats = attributes.get("last_analysis_stats", {})
    flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values()) or 0
    if flagged:
        signals.append(
            Signal(
                id="virustotal_detections",
                source="VirusTotal v3",
                value=f"{flagged}/{total} security vendors flagged this domain",
                weight=50 if flagged >= 3 else 25,
            )
        )
    if registrar := attributes.get("registrar"):
        signals.append(
            Signal(
                id="registrar",
                source="VirusTotal v3 (registrar record)",
                value=str(registrar),
                weight=0,  # context for the human, not evidence of fraud
            )
        )
    return signals


def _age_signal(created: datetime, source: str) -> list[Signal]:
    days = (datetime.now(timezone.utc) - created).days
    if days < 0:
        return []
    if days <= 30:
        weight = 40
    elif days <= 180:
        weight = 20
    else:
        weight = 0
    return [
        Signal(
            id="domain_age",
            source=source,
            value=f"registered {days} day(s) ago on {created.date().isoformat()}",
            weight=weight,
        )
    ]


def domain_age(domain: str) -> list[Signal]:
    """Registration date via RDAP. No API key needed, and the single
    strongest signal there is: real banks are not two weeks old."""
    if is_offline():
        return []

    cache_key = f"rdap_{domain}"
    events = _cached(cache_key, ttl_hours=24 * 7)
    if events is None:
        try:
            response = httpx.get(
                f"https://rdap.org/domain/{domain}",
                timeout=_TIMEOUT,
                follow_redirects=True,
            )
            response.raise_for_status()
            events = response.json().get("events", [])
        except (httpx.HTTPError, json.JSONDecodeError):
            return []
        _store(cache_key, events)

    for event in events:
        if event.get("eventAction") == "registration":
            try:
                created = datetime.fromisoformat(
                    event["eventDate"].replace("Z", "+00:00")
                )
            except (ValueError, KeyError):
                return []
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return _age_signal(created, "RDAP (domain registry)")
    return []


def tls_certificate(host: str) -> list[Signal]:
    """Certificate issuer and age, read straight off the TLS handshake."""
    if is_offline():
        return []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return []
    if not cert:
        return []

    signals: list[Signal] = []
    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    if name := issuer.get("organizationName"):
        signals.append(
            Signal(
                id="tls_issuer",
                source="TLS certificate (live handshake)",
                value=f"issued by {name}",
                weight=0,
            )
        )
    if not_before := cert.get("notBefore"):
        try:
            issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return signals
        age = (datetime.now(timezone.utc) - issued).days
        signals.append(
            Signal(
                id="tls_age",
                source="TLS certificate (live handshake)",
                value=f"certificate issued {age} day(s) ago",
                weight=25 if age <= 14 else 0,
            )
        )
    return signals


def enrich(subject_type: str, value: str, host: str, domain: str) -> list[Signal]:
    """Every network check that applies. Returns [] when offline."""
    if is_offline() or subject_type not in ("url", "domain"):
        return []

    signals: list[Signal] = []
    if subject_type == "url":
        signals += safe_browsing(value)
    signals += virustotal(domain)
    signals += domain_age(domain)
    signals += tls_certificate(host)
    return signals
