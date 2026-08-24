"""Privacy / compliance safeguards [SIH26106 KC6 / #10]."""

from pathlib import Path

from fastapi.testclient import TestClient

from app import privacy
from app.main import app

client = TestClient(app)
EMAILS = Path(__file__).resolve().parents[3] / "fixtures" / "email"


def _phish() -> str:
    return (EMAILS / "phishing_kyc.eml").read_text(encoding="utf-8")


def test_mask_helpers():
    assert privacy.mask_email("victim@recipient.gov.in").startswith("v***@")
    assert privacy.mask_email("victim@recipient.gov.in").endswith(".in")
    assert privacy.mask_phone("+91 9876543210") == "91********10"  # keeps 2 head + 2 tail digits
    assert privacy.mask_ip("185.220.101.5") == "185.220.x.x"


def test_masking_off_by_default():
    body = client.post("/check/email", data={"raw": _phish(), "language": "en"}).json()
    f = body["email_forensics"]
    assert f["from_addr"] == "alerts@hdfcbank-secure.top"  # unmasked
    assert not f.get("pii_masked")


def test_masking_on_hides_pii_in_the_display():
    body = client.post("/check/email", data={"raw": _phish(), "language": "en", "mask": "true"}).json()
    f = body["email_forensics"]
    assert f["pii_masked"] is True
    assert "@" in f["from_addr"] and "hdfcbank-secure" not in f["from_addr"]  # masked
    assert f["to"].startswith("v***@")
    assert f["originating_ip"] == "185.220.x.x"


def test_case_file_keeps_real_evidence_even_when_display_is_masked():
    # Chain-of-custody evidence must not be masked; only the display is.
    body = client.post("/check/email", data={"raw": _phish(), "language": "en", "case": "true", "mask": "true"}).json()
    assert body["email_forensics"]["pii_masked"] is True
    assert body["case_file"]["subject_email"]["from"] == "alerts@hdfcbank-secure.top"  # real


def test_case_export_is_logged_as_preservation_event():
    client.post("/check/email", data={"raw": _phish(), "case": "true"})
    events = client.get("/ledger/events").json()["events"]
    assert any(e.get("event_type") == "preservation" for e in events)


def test_privacy_policy_endpoint():
    p = client.get("/privacy/policy").json()
    assert "retention_days" in p and isinstance(p["retention_days"], int)
    assert "evidence_preservation" in p and "never purged" in p["evidence_preservation"].lower()
