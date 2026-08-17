"""NCRP / 1930-aligned evidence packet export.

The user has a verdict and a tamper-evident log. To be *useful* that has to
come out in the shape the complaint rails actually ask for, so a victim can
transcribe it into cybercrime.gov.in or read it to the 1930 helpline without
hunting for details while panicking.

Field names mirror what NCRP's financial-fraud flow asks for. Veris does not
submit anything: there is no public NCRP API, and auto-filing on someone's
behalf would be wrong even if there were. The user decides, always.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from . import ENGINE_VERSION
from .ledger import anchor_status, read_all, verify


class ComplaintDetails(BaseModel):
    """What NCRP's financial-fraud form asks for. Everything is optional --
    a victim reporting within the golden hour will not have it all."""

    incident_datetime: str | None = None  # ISO-8601, when it happened
    amount_lost: float | None = None  # INR
    payment_mode: str | None = None  # UPI / IMPS / NEFT / card / wallet
    suspect_upi_id: str | None = None
    suspect_account_number: str | None = None
    suspect_bank_or_wallet: str | None = None
    transaction_reference: str | None = None  # UTR / txn id
    victim_bank_or_wallet: str | None = None
    suspect_phone: str | None = None
    suspect_urls: list[str] = Field(default_factory=list)
    screenshot_sha256: list[str] = Field(default_factory=list)
    description: str | None = None


ATTRIBUTION = [
    "URL reputation: Advisory provided by Google (Safe Browsing)",
    "Domain and file reputation: VirusTotal",
    "Blocklists: PhishTank, URLhaus (abuse.ch), OpenPhish",
    "Registration data: RDAP",
    "Confusable detection: Unicode UTS #39",
]

REPORTING_RAILS = [
    {
        "name": "National Cyber Crime Reporting Portal (NCRP)",
        "url": "https://cybercrime.gov.in/",
        "note": "File the complaint here. No public API: the user submits this themselves.",
    },
    {
        "name": "Cyber Financial Fraud helpline 1930",
        "url": "tel:1930",
        "note": "Call within the golden hour to attempt transaction freeze.",
    },
    {
        "name": "Sanchar Saathi / Chakshu",
        "url": "https://sancharsaathi.gov.in/",
        "note": "Report fraudulent calls and SMS. Deep-link only, no public API.",
    },
]


def build_packet(complaint: ComplaintDetails) -> dict:
    """Assemble the packet: complaint fields, evidence, and chain status.

    The verification result is embedded deliberately. A packet that says
    "chain intact, head <hash>" is checkable by whoever receives it; one that
    quietly omits a broken chain would be evidence laundering.
    """
    chain = verify()
    events = read_all()

    findings = [
        {
            "seq": event["seq"],
            "recorded_at": event["recorded_at"],
            "checked": event["payload"].get("subject", {}).get("value"),
            "verdict": event["payload"].get("verdict"),
            "score": event["payload"].get("score"),
            "rules_fired": event["payload"].get("rules_fired", []),
            "signals": [
                {"source": s.get("source"), "observed": s.get("value"), "observed_at": s.get("observed_at")}
                for s in event["payload"].get("signals", [])
            ],
        }
        for event in events
        if event.get("event_type") == "check"
    ]

    return {
        "packet_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": f"Veris verdict engine {ENGINE_VERSION}",
        "complaint": complaint.model_dump(),
        "automated_findings": findings,
        "evidence_ledger": {
            "events": events,
            "chain_verified": chain["ok"],
            "chain_status": chain["reason"],
            "broken_at_seq": chain["broken_at"],
            "head_hash": chain["head_hash"],
            "head_signature": chain["head_signature"],
            "signing_key": chain["signing_key"],
            "timestamp_anchoring": anchor_status(),
            "how_to_verify": (
                "Recompute SHA-256 over each record with its 'hash' field removed and "
                "keys sorted, then confirm each record's prev_hash equals the previous "
                "record's hash. Any edit breaks every link after it."
            ),
        },
        "data_sources": ATTRIBUTION,
        "where_to_report": REPORTING_RAILS,
        "disclaimer": (
            "Automated assessment for the recipient's consideration. Verdicts are "
            "'likely' assessments produced by deterministic checks against the cited "
            "sources, not a determination of guilt against any person or company. "
            "Veris did not submit this report to any authority."
        ),
    }
