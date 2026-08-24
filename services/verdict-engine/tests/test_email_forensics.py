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


def test_origin_geolocation_tor_and_claim_mismatch():
    resp = client.post("/check/email", data={"raw": _load("phishing_kyc.eml"), "language": "en"})
    body = resp.json()
    ids = {s["id"] for s in body["signals"]}
    assert "email_origin_geo" in ids
    assert "email_origin_tor" in ids  # 185.220.101.5 is a bundled TOR exit
    assert "email_origin_mismatch" in ids  # claims HDFC (India), originates Germany
    assert body["email_forensics"]["geo"]["country_code"] == "DE"


def test_sender_domain_intel_flags_new_domain_and_no_mx():
    resp = client.post("/check/email", data={"raw": _load("phishing_kyc.eml"), "language": "en"})
    body = resp.json()
    ids = {s["id"] for s in body["signals"]}
    assert "email_domain_new" in ids  # hdfcbank-secure.top registered days ago
    assert "email_domain_no_mx" in ids  # no MX -> spoofing tell
    assert body["email_forensics"]["domain_intel"]["registrar"]


def test_verdict_is_never_written_by_this_module():
    # analyze_email only gathers signals; it has no verdict field to set.
    signals, meta = analyze_email(_load("phishing_kyc.eml"))
    assert all(hasattr(s, "weight") for s in signals)
    assert "verdict" not in meta


def test_ml_signal_is_emitted_and_capped():
    from app.ml_classifier import ml_signal

    body = client.post("/check/email", data={"raw": _load("phishing_kyc.eml"), "language": "en"}).json()
    ml = [s for s in body["signals"] if s["id"] == "ml_phishing_likelihood"]
    assert ml, "ML phishing-likelihood signal should be emitted"
    assert ml[0]["weight"] <= 30  # capped -> can never override a hard signal
    # the model discriminates phishing from legit text
    phish = ml_signal("verify your account and confirm your OTP immediately or it will be blocked")
    legit = ml_signal("your monthly statement is ready in the portal, thank you for banking with us")
    assert phish and legit and phish.weight >= legit.weight


def test_forensic_case_file_is_prosecution_ready():
    body = client.post("/check/email", data={"raw": _load("phishing_kyc.eml"), "language": "en", "case": "true"}).json()
    cf = body["case_file"]
    assert cf["classification"] == "impersonated"
    assert cf["verdict"] == "likely_scam"
    # grouped forensic sections
    assert cf["findings"]["authentication"]
    assert cf["findings"]["origin_and_geolocation"]
    assert cf["findings"]["domain_intelligence"]
    # chain-of-custody with a verifiable ledger status
    coc = cf["chain_of_custody"]
    assert coc["recorded_in_ledger"] is True
    assert coc["ledger_verified"] is True  # fresh isolated ledger
    assert coc["head_hash"] and coc["evidence_digest"]
    # reporting rails include CERT-In
    assert any("CERT-In" in r["name"] for r in cf["where_to_report"])


def test_case_file_reports_a_broken_chain_rather_than_hiding_it(monkeypatch):
    # Chain-of-custody integrity must be surfaced, not laundered.
    from app import case_file

    monkeypatch.setattr(case_file, "verify", lambda: {
        "ok": False, "reason": "contents were altered at seq 3", "broken_at": 3,
        "head_hash": None, "head_signature": None, "signing_key": "dev",
    })
    cf = case_file.build_email_case({"verdict": "likely_scam", "score": 90, "signals": []}, {"message_id": "<x@y>"})
    assert cf["chain_of_custody"]["ledger_verified"] is False
    assert "altered" in cf["chain_of_custody"]["ledger_status"]


def test_four_emails_cluster_into_one_campaign():
    from app.campaign import correlate

    raws = [p.read_text(encoding="utf-8") for p in sorted((EMAILS / "campaign").glob("*.eml"))]
    assert len(raws) == 4
    result = correlate(raws)
    assert result["email_count"] == 4
    assert result["campaign_count"] == 1  # "these 4 = 1 campaign"
    camp = max(result["campaigns"], key=lambda c: c["size"])
    assert camp["size"] == 4
    assert camp["confidence"] > 0.5
    # shared infrastructure was identified across the 4 spoofed senders
    assert "originating_ip" in camp["shared_artifacts"]
    assert "xmailer" in camp["shared_artifacts"] or "reply_to" in camp["shared_artifacts"]
    assert camp["attribution"] in ("spoofed_domain", "anonymized_infrastructure", "direct_actor")


def test_unrelated_emails_do_not_cluster():
    from app.campaign import correlate

    raws = [_load("phishing_kyc.eml"), _load("legit_statement.eml")]
    result = correlate(raws)
    assert result["campaign_count"] == 0  # no shared infrastructure


def test_campaign_endpoint_needs_at_least_two():
    resp = client.post("/email/campaign", files=[("files", ("a.eml", _load("phishing_kyc.eml"), "message/rfc822"))])
    assert resp.status_code == 422


def test_empty_input_is_rejected():
    assert client.post("/check/email", data={}).status_code == 422
