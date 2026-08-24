"""Privacy, legal & compliance safeguards [SIH26106 KC6 / #10].

Three cheap-but-high-value capabilities most teams skip:
- PII masking of sensitive communication data (visible in the demo), toggleable.
- A configurable retention policy, exposed for audit. NOTE: the tamper-evident
  ledger is evidence -- it is append-only and never purged; retention/masking
  govern the transient PII surface, not the chain-of-custody record.
- Evidence-preservation logging: every case-file export is recorded into the
  hash-chained ledger as a preservation event, so access itself is auditable.

None of this touches the verdict, the hash chain, or /ledger/verify.
"""

from __future__ import annotations

import hashlib
import os
import re

from .ledger import append

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"\+?\d[\d\s-]{7,}\d")


def masking_enabled(override: bool | None = None) -> bool:
    if override is not None:
        return override
    return os.getenv("VERIS_MASK_PII", "0") == "1"


def mask_email(addr: str) -> str:
    if not addr or "@" not in addr:
        return addr
    local, _, domain = addr.partition("@")
    local_m = (local[0] + "***") if local else "***"
    if "." in domain:
        name, _, tld = domain.rpartition(".")
        domain_m = f"{name[0]}***.{tld}" if name else f"***.{tld}"
    else:
        domain_m = (domain[0] + "***") if domain else "***"
    return f"{local_m}@{domain_m}"


def mask_phone(text: str) -> str:
    digits = re.sub(r"\D", "", text)
    if len(digits) < 7:
        return text
    return digits[:2] + "*" * (len(digits) - 4) + digits[-2:]


def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else ip


def _scrub(text: str) -> str:
    text = _EMAIL.sub(lambda m: mask_email(m.group(0)), text)
    text = _PHONE.sub(lambda m: mask_phone(m.group(0)), text)
    return text


def mask_forensics(forensics: dict, enabled: bool) -> dict:
    """Return a copy with victim/PII fields masked when masking is on."""
    if not enabled:
        return forensics
    f = dict(forensics)
    if f.get("from_addr"):
        f["from_addr"] = mask_email(f["from_addr"])
    if f.get("reply_to"):
        f["reply_to"] = f["reply_to"]  # a domain, not PII; kept for forensics
    if f.get("to"):
        f["to"] = mask_email(f["to"])
    if f.get("subject"):
        f["subject"] = _scrub(f["subject"])
    if f.get("originating_ip"):
        f["originating_ip"] = mask_ip(f["originating_ip"])
    f["pii_masked"] = True
    return f


def retention_policy() -> dict:
    return {
        "pii_masking": masking_enabled(),
        "retention_days": int(os.getenv("VERIS_RETENTION_DAYS", "90")),
        "evidence_preservation": (
            "The tamper-evident ledger is append-only and NEVER purged -- evidence "
            "preservation overrides retention. Retention/masking govern only the "
            "transient PII surface (request/response), not the chain-of-custody record."
        ),
        "chain_of_custody": "SHA-256 hash chain with a signed head; access is logged as preservation events.",
    }


def log_preservation(action: str, evidence_digest: str) -> None:
    """Record an evidence access/export into the ledger (auditable access log)."""
    append("preservation", {"action": action, "evidence_digest": evidence_digest, "policy": {"retention_days": retention_policy()["retention_days"]}})


def evidence_digest(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()
