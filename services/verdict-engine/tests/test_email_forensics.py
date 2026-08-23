"""Email threat forensics end-to-end, fully offline [SIH26106].

A seeded malicious .eml must flow through the UNCHANGED engine (signals ->
decide -> verdict -> ledger) and come out as a cited, court-defensible verdict.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from app.email_forensics import analyze_email, originating_ip, parse_eml
from app.main import app

client = TestClient(app)
EMAILS = Path(__file__).resolve().parents[3] / "fixtures" / "email"


def _load(name: str) -> str:
    return (EMAILS / name).read_text(encoding="utf-8")


def test_phishing_email_is_flagged_with_cited_signals():
    resp = client.post("/check/email", data={"raw": _load("phishing_kyc.eml"), "language": "en"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "likely_scam"
    ids = {s["id"] for s in body["signals"]}
    # header forensics fired
    assert "email_auth_dmarc" in ids
    assert "email_from_returnpath_mismatch" in ids
    assert "email_replyto_mismatch" in ids
    # the body link ran through the EXISTING url engine (homoglyph)
    assert any(i.startswith("homoglyph") for i in ids)
    # 5-label classification, deterministic
    assert body["email_forensics"]["classification"] in ("impersonated", "phishing")


def test_legit_email_passes():
    resp = client.post("/check/email", data={"raw": _load("legit_statement.eml")})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "safe"
    assert body["email_forensics"]["classification"] == "legitimate"
    assert body["email_forensics"]["auth_results"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_bec_invoice_is_classified_fraud_related():
    resp = client.post("/check/email", data={"raw": _load("bec_invoice.eml"), "language": "en"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "likely_scam"
    ids = {s["id"] for s in body["signals"]}
    assert "email_lang_payment_diversion" in ids  # BEC language
    assert "email_lang_fake_invoice" in ids
    assert body["email_forensics"]["classification"] == "fraud-related"


def test_originating_ip_is_the_earliest_public_hop():
    signals, meta = analyze_email(_load("phishing_kyc.eml"))
    # 10.0.0.5 is private (the receiver); the true origin is the public sender.
    assert meta["originating_ip"] == "185.220.101.5"


def test_verdict_is_never_written_by_this_module():
    # analyze_email only gathers signals; it has no verdict field to set.
    signals, meta = analyze_email(_load("phishing_kyc.eml"))
    assert all(hasattr(s, "weight") for s in signals)
    assert "verdict" not in meta


def test_empty_input_is_rejected():
    assert client.post("/check/email", data={}).status_code == 422
