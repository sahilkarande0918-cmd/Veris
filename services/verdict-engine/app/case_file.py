"""Prosecution-ready forensic case file for an analyzed email [SIH26106 KC5/#7].

Assembles the full email analysis into a structured, chain-of-custody evidence
record for legal review / incident response / law-enforcement. It does NOT
produce the verdict or touch the chain -- it embeds the already-decided
VerdictResult and the CURRENT ledger integrity status (signed head + verify),
so whoever receives the case file can independently re-verify it. A broken chain
is reported, never hidden.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from . import ENGINE_VERSION
from .ledger import anchor_status, verify

# Which cited signals belong to which section of the forensic report.
_SECTIONS = {
    "authentication": lambda i: i.startswith("email_auth_"),
    "spoofing_and_identity": lambda i: i in {"email_from_returnpath_mismatch", "email_replyto_mismatch", "email_display_name_spoof"},
    "origin_and_geolocation": lambda i: i.startswith("email_origin_"),
    "domain_intelligence": lambda i: i.startswith("email_domain_"),
    "content_and_ml": lambda i: i.startswith("email_lang_") or i == "ml_phishing_likelihood",
}

REPORTING_RAILS = [
    {"name": "CERT-In (incident reporting)", "url": "https://www.cert-in.org.in/", "note": "Report to the national CERT within the mandated window; attach this case file."},
    {"name": "National Cyber Crime Reporting Portal (NCRP)", "url": "https://cybercrime.gov.in/", "note": "File the complaint here. No public API: the user submits this."},
    {"name": "Cyber Financial Fraud helpline 1930", "url": "tel:1930", "note": "Call within the golden hour to attempt a transaction freeze (financial fraud)."},
]


def build_email_case(result: dict, forensics: dict) -> dict:
    """Wrap a decided email VerdictResult + its forensics into a case file."""
    signals = result.get("signals", [])

    def section(pred) -> list[dict]:
        return [
            {"source": s.get("source"), "finding": s.get("value"), "weight": s.get("weight"), "observed_at": s.get("observed_at")}
            for s in signals
            if pred(s.get("id", ""))
        ]

    findings = {name: section(pred) for name, pred in _SECTIONS.items()}
    findings["links_and_reputation"] = [
        {"source": s.get("source"), "finding": s.get("value"), "weight": s.get("weight"), "observed_at": s.get("observed_at")}
        for s in signals
        if not any(pred(s.get("id", "")) for pred in _SECTIONS.values())
    ]

    evidence_hash = hashlib.sha256(
        (forensics.get("message_id", "") + str(result.get("score", "")) + result.get("verdict", "")).encode()
    ).hexdigest()

    chain = verify()

    return {
        "case_file_version": "1.0",
        "case_id": (forensics.get("message_id") or f"email-{evidence_hash[:12]}").strip("<>"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": f"Veris forensic engine {ENGINE_VERSION}",
        "classification": forensics.get("classification"),
        "verdict": result.get("verdict"),
        "risk_score": result.get("score"),
        "subject_email": {
            "from": forensics.get("from_addr"),
            "from_display_name": forensics.get("from_name"),
            "subject": forensics.get("subject"),
            "message_id": forensics.get("message_id"),
            "return_path": forensics.get("return_path"),
            "reply_to": forensics.get("reply_to"),
            "originating_ip": forensics.get("originating_ip"),
            "geolocation": forensics.get("geo"),
            "received_hops": forensics.get("received_hops"),
        },
        "findings": findings,
        "explanation": result.get("explanation"),
        "chain_of_custody": {
            "recorded_in_ledger": True,
            "evidence_digest": evidence_hash,
            "ledger_verified": chain["ok"],
            "ledger_status": chain["reason"],
            "head_hash": chain["head_hash"],
            "head_signature": chain["head_signature"],
            "signing_key": chain["signing_key"],
            "timestamp_anchoring": anchor_status(),
            "how_to_verify": (
                "Recompute SHA-256 over each ledger record (its 'hash' field removed, keys "
                "sorted) and confirm each record's prev_hash equals the previous record's "
                "hash. Any edit breaks every link after it; /ledger/verify names the first."
            ),
        },
        "where_to_report": REPORTING_RAILS,
        "disclaimer": (
            "Automated forensic assessment for the recipient's consideration. Verdict and "
            "classification are produced by deterministic checks against the cited sources; "
            "the ML model contributes one weighted signal and does not decide. Geolocation "
            "and attribution are probabilistic investigative aids, not a determination of "
            "guilt against any person. Veris submitted this to no authority."
        ),
    }
