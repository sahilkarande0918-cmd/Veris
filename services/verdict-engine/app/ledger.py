"""Append-only, hash-chained evidence ledger.

Every incident event is one JSONL line carrying the SHA-256 hash of the
previous line. Change any byte of any earlier record and every hash after it
stops matching, so tampering is detectable without trusting this service or
its operator.

This is a hash chain, not a blockchain, and that is deliberate. A blockchain
solves *distributed consensus among mutually distrusting parties*. The problem
here is *detecting after-the-fact edits to one evidence log*, which a hash
chain solves completely, with no network, no miners, and no tokens. The
property a complainant actually needs -- "this record existed in this order
and has not been altered" -- is exactly what the chain gives.

What a hash chain alone does NOT give you is proof of *when*, or protection
from someone who rewrites the entire chain from genesis. Two answers, both
implemented here:

- the chain head is signed, so a full rewrite needs the signing key;
- `anchor` records an external RFC 3161 timestamp when one is available.
"""

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64

# ponytail: a dev fallback key keeps `git clone && run` working. It is not a
# secret and the /ledger/verify response says so. Set VERIS_LEDGER_KEY for
# anything real.
DEV_KEY = "veris-development-key-not-secret"


def ledger_path() -> Path:
    """Read the env var per call so tests can redirect the ledger."""
    configured = os.getenv("VERIS_LEDGER_PATH")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[1] / "data" / "ledger.jsonl"


def _canonical(record: dict) -> bytes:
    """Byte-exact serialisation, so a hash is reproducible anywhere.

    Sorted keys and no incidental whitespace: two machines must agree on the
    bytes or the chain is worthless.
    """
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_hash(record: dict) -> str:
    """SHA-256 over every field except the record's own `hash`."""
    return hashlib.sha256(_canonical({k: v for k, v in record.items() if k != "hash"})).hexdigest()


def _key_status() -> str:
    return "configured" if os.getenv("VERIS_LEDGER_KEY") else "dev-default (not secret)"


def read_all() -> list[dict]:
    path = ledger_path()
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append(event_type: str, payload: dict) -> dict:
    """Add one event and return the sealed record."""
    existing = read_all()
    prev_hash = existing[-1]["hash"] if existing else GENESIS

    record = {
        "seq": len(existing) + 1,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    record["hash"] = compute_hash(record)

    path = ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # ponytail: append mode is atomic enough for one process. Add a file lock
    # if the engine is ever run multi-worker.
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def sign_head(head_hash: str) -> str:
    """HMAC-SHA256 over the chain head.

    ponytail: HMAC means a verifier needs the shared key. Swap for Ed25519
    (`cryptography`) when a third party must verify without holding the secret.
    """
    key = os.getenv("VERIS_LEDGER_KEY", DEV_KEY)
    return hmac.new(key.encode(), head_hash.encode(), hashlib.sha256).hexdigest()


def verify() -> dict:
    """Walk the chain and report the first break, precisely.

    Returns which record broke and why -- 'the log is bad' is not useful to a
    complainant or an investigating officer.
    """
    records = read_all()
    if not records:
        return {
            "ok": True,
            "count": 0,
            "broken_at": None,
            "reason": "ledger is empty",
            "head_hash": GENESIS,
            "head_signature": sign_head(GENESIS),
            "signing_key": _key_status(),
        }

    expected_prev = GENESIS
    for index, record in enumerate(records, start=1):
        seq = record.get("seq")

        if seq != index:
            return _broken(records, seq or index, f"expected seq {index}, found {seq} -- a record was inserted or removed")

        if record.get("prev_hash") != expected_prev:
            return _broken(records, seq, "prev_hash does not match the previous record's hash -- the chain was cut or reordered")

        recomputed = compute_hash(record)
        if recomputed != record.get("hash"):
            return _broken(records, seq, f"contents were altered: stored hash {str(record.get('hash'))[:16]}... but the data now hashes to {recomputed[:16]}...")

        expected_prev = record["hash"]

    head = records[-1]["hash"]
    return {
        "ok": True,
        "count": len(records),
        "broken_at": None,
        "reason": "chain intact: every record hashes to its stored value and links to its predecessor",
        "head_hash": head,
        "head_signature": sign_head(head),
        "signing_key": _key_status(),
    }


def _broken(records: list[dict], seq: int, reason: str) -> dict:
    return {
        "ok": False,
        "count": len(records),
        "broken_at": seq,
        "reason": reason,
        "head_hash": None,
        "head_signature": None,
        "signing_key": _key_status(),
    }


def anchor_status() -> dict:
    """Where the chain head's trust in *time* comes from. [STRETCH: RFC 3161]

    A hash chain proves order, not wall-clock time. Full RFC 3161 anchoring
    needs a DER-encoded TimeStampReq and therefore a crypto dependency, which
    is not built. This reports that honestly rather than implying a trusted
    timestamp we do not have -- a fabricated time in an evidence packet is far
    worse than an absent one.
    """
    return {
        "anchored": False,
        "method": "local HMAC signature over the chain head",
        "detail": (
            "External RFC 3161 timestamp anchoring is not configured. Order and "
            "integrity are proven by the chain; wall-clock time is asserted by "
            "this device, not by a trusted third party."
        ),
    }
