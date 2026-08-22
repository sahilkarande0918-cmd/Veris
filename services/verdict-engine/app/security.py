"""Opt-in API auth + per-endpoint rate limiting (Tier 2 #7).

Offline-first, like every other external in this engine: with no
``VERIS_AUTH_SECRET`` set, auth is OFF and the engine is open -- exactly what a
local/LAN/offline demo and the test suite need. Set the secret on a public host
and only devices holding a valid token can call it. That is where quota-burn
abuse actually lives (a hosted engine calling Groq/VirusTotal on someone's key).

Tokens are stateless: ``<device_id>.<hmac_sha256(secret, device_id)>``. No
database -- validation just recomputes the HMAC. Rate limits are keyed per
device (or per client IP when auth is off) and enforced per endpoint.

ponytail: the rate limiter is an in-process sliding window. Correct for the
single-instance engine we ship; front it with a shared store (Redis) only if
you ever run replicas.
"""

import hashlib
import hmac
import os
import time
from collections import defaultdict, deque

# Per-endpoint limits: path -> (max_requests, window_seconds). Generous enough
# that a live demo never trips; the APK path is stricter because it decompiles.
LIMITS: dict[str, tuple[int, int]] = {
    "/check": (60, 60),
    "/check/qr": (60, 60),
    "/check/apk": (10, 60),
    "/ledger/report": (30, 60),
    "_default": (120, 60),
}

_hits: dict[tuple[str, str], deque] = defaultdict(deque)


def _secret() -> str | None:
    return os.getenv("VERIS_AUTH_SECRET") or None


def auth_enabled() -> bool:
    """True only when an operator has set VERIS_AUTH_SECRET (i.e. on a host)."""
    return _secret() is not None


def mint_token(device_id: str) -> str:
    """Issue a stateless token for a device. Uniform whether or not auth is on."""
    secret = _secret() or "veris-open"
    sig = hmac.new(secret.encode(), device_id.encode(), hashlib.sha256).hexdigest()
    return f"{device_id}.{sig}"


def valid_token(token: str) -> str | None:
    """Return the device_id if the token is authentic for the current secret."""
    secret = _secret()
    if not secret or not token or "." not in token:
        return None
    device_id, _, sig = token.rpartition(".")
    expected = hmac.new(secret.encode(), device_id.encode(), hashlib.sha256).hexdigest()
    return device_id if device_id and hmac.compare_digest(sig, expected) else None


def check_rate(key: str, path: str) -> bool:
    """True if allowed; False if `key` exceeded the limit for `path`."""
    limit, window = LIMITS.get(path, LIMITS["_default"])
    now = time.monotonic()
    dq = _hits[(key, path)]
    while dq and dq[0] <= now - window:
        dq.popleft()
    if len(dq) >= limit:
        return False
    dq.append(now)
    return True


def reset_rate_limits() -> None:
    """Clear all rate-limit state. For tests only."""
    _hits.clear()
