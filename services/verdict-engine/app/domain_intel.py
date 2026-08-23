"""Sender-domain intelligence: WHOIS + DNS/MX [SIH26106 KC3].

Offline-first enrichment, same contract as geo: a bundled offline map serves the
demo/seed domains so it runs with the network off; online, `python-whois` +
`dnspython` (cached) supersede it. Findings are cited `Signal`s; the verdict is
still `rules.decide()`. Everything degrades to [] on any failure.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from verdict import Signal

from .enrich import _cached, _store, is_offline

_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "domain"


@lru_cache(maxsize=1)
def _offline_map() -> dict:
    try:
        return json.loads((_DIR / "offline_domain_intel.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _age_days(created) -> int | None:
    if created is None:
        return None
    if isinstance(created, list):
        created = created[0]
    if isinstance(created, str):
        try:
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - created).days


def domain_intel(domain: str) -> dict:
    """{registrar, age_days, name_servers, mx} for a domain, or {}.

    Offline map first (works offline), then cache, then live WHOIS + DNS.
    """
    if not domain:
        return {}
    offline = _offline_map().get(domain)
    if offline:
        return offline

    cache_key = f"dintel_{domain}"
    cached = _cached(cache_key, ttl_hours=24)
    if cached is not None:
        return cached
    if is_offline():
        return {}

    intel: dict = {}
    try:
        import whois  # python-whois; imported lazily so the service starts without it

        w = whois.whois(domain)
        intel["registrar"] = w.registrar or ""
        intel["age_days"] = _age_days(w.creation_date)
        intel["name_servers"] = [str(n).lower() for n in (w.name_servers or [])][:4]
    except Exception:  # noqa: BLE001 - a WHOIS failure must never break a verdict
        pass
    try:
        import dns.resolver

        intel["mx"] = sorted(str(r.exchange).rstrip(".").lower() for r in dns.resolver.resolve(domain, "MX"))
    except Exception:  # noqa: BLE001
        intel.setdefault("mx", [])

    if intel:
        _store(cache_key, intel)
    return intel


def domain_signals(domain: str) -> tuple[list[Signal], dict]:
    """Cited signals from the sender domain's registration + DNS footprint."""
    intel = domain_intel(domain)
    signals: list[Signal] = []
    if not intel:
        return signals, {}

    age = intel.get("age_days")
    if isinstance(age, int) and age >= 0:
        if age <= 30:
            signals.append(
                Signal(
                    id="email_domain_new",
                    source="WHOIS (sender domain registration)",
                    value=f"sender domain registered {age} day(s) ago -- freshly created infrastructure",
                    weight=20,
                )
            )
        signals.append(
            Signal(
                id="email_domain_registration",
                source="WHOIS (sender domain registration)",
                value=f"registered {age} day(s) ago via {intel.get('registrar', 'unknown registrar')}",
                weight=0,
            )
        )

    if "mx" in intel and not intel["mx"]:
        signals.append(
            Signal(
                id="email_domain_no_mx",
                source="DNS (sender domain MX records)",
                value="sender domain has no MX record -- it cannot receive mail, a spoofing tell",
                weight=15,
            )
        )
    return signals, intel
