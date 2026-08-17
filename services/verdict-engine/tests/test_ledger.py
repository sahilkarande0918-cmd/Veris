"""Phase 3: the hash chain must catch every way of editing the log.

Each test tampers differently -- edit in place, forge the hash, delete a
record, reorder, append a forged tail -- because "we hash things" is only
worth something if it survives an attacker who also knows that.
"""

import json

import pytest

from app.ledger import GENESIS, append, compute_hash, ledger_path, read_all, sign_head, verify
from app.packet import ComplaintDetails, build_packet


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """Ledger isolation is handled globally in conftest.py."""
    monkeypatch.setenv("VERIS_OFFLINE", "1")


def seed(count: int = 3) -> list[dict]:
    return [append("check", {"subject": {"value": f"http://scam-{i}.test"}, "verdict": "likely_scam", "score": 70, "signals": [], "rules_fired": []}) for i in range(count)]


def rewrite(records: list[dict]) -> None:
    ledger_path().write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8"
    )


# --- the happy path --------------------------------------------------------


def test_empty_ledger_verifies():
    assert verify()["ok"] is True
    assert verify()["count"] == 0


def test_three_appends_produce_an_intact_chain():
    seed(3)
    status = verify()
    assert status["ok"] is True
    assert status["count"] == 3
    assert status["head_hash"]
    assert status["head_signature"]


def test_each_record_links_to_the_previous_one():
    seed(3)
    records = read_all()
    assert records[0]["prev_hash"] == GENESIS
    for earlier, later in zip(records, records[1:]):
        assert later["prev_hash"] == earlier["hash"]
        assert later["seq"] == earlier["seq"] + 1


# --- tampering, five ways --------------------------------------------------


def test_editing_a_payload_is_caught():
    """The headline demo: change a verdict after the fact."""
    seed(3)
    records = read_all()
    records[1]["payload"]["verdict"] = "safe"  # the lie
    rewrite(records)

    status = verify()
    assert status["ok"] is False
    assert status["broken_at"] == 2
    assert "altered" in status["reason"]


def test_editing_a_payload_and_recomputing_the_hash_is_still_caught():
    """A smarter attacker fixes the record's own hash. The *next* record's
    prev_hash still points at the old one."""
    seed(3)
    records = read_all()
    records[1]["payload"]["verdict"] = "safe"
    records[1]["hash"] = compute_hash(records[1])  # forged to be self-consistent
    rewrite(records)

    status = verify()
    assert status["ok"] is False
    assert status["broken_at"] == 3
    assert "prev_hash" in status["reason"]


def test_deleting_a_record_is_caught():
    seed(3)
    records = read_all()
    del records[1]
    rewrite(records)

    status = verify()
    assert status["ok"] is False
    assert status["broken_at"] == 3
    assert "inserted or removed" in status["reason"]


def test_reordering_records_is_caught():
    seed(3)
    records = read_all()
    records[0], records[1] = records[1], records[0]
    rewrite(records)

    assert verify()["ok"] is False


def test_appending_a_forged_record_is_caught():
    """Someone adds an event that never happened, without the real prev_hash."""
    seed(2)
    records = read_all()
    forged = {
        "seq": 3,
        "recorded_at": "2026-01-01T00:00:00+00:00",
        "event_type": "check",
        "payload": {"verdict": "safe"},
        "prev_hash": GENESIS,  # wrong: should chain to record 2
    }
    forged["hash"] = compute_hash(forged)
    rewrite(records + [forged])

    status = verify()
    assert status["ok"] is False
    assert status["broken_at"] == 3


def test_a_tampered_chain_changes_the_head_signature():
    seed(3)
    original_head = verify()["head_hash"]

    records = read_all()
    records[2]["payload"]["verdict"] = "safe"
    records[2]["hash"] = compute_hash(records[2])
    rewrite(records)

    # The chain still verifies structurally only if the break is at the tail,
    # so what protects the tail is the signature over a now-different head.
    assert read_all()[2]["hash"] != original_head
    assert sign_head(read_all()[2]["hash"]) != sign_head(original_head)


# --- the complaint packet --------------------------------------------------


def test_packet_carries_ncrp_fields_and_the_chain_status():
    seed(2)
    complaint = ComplaintDetails(
        incident_datetime="2026-08-18T10:30:00+05:30",
        amount_lost=45000.0,
        payment_mode="UPI",
        suspect_upi_id="kycupdate2026@ybl",
        suspect_bank_or_wallet="PhonePe",
        transaction_reference="UTR123456789",
        suspect_phone="9876543210",
        suspect_urls=["http://sbi-kyc-verify-online.top/login"],
        screenshot_sha256=["a" * 64],
        description="Received an SMS about KYC expiry and paid.",
    )
    packet = build_packet(complaint)

    assert packet["complaint"]["amount_lost"] == 45000.0
    assert packet["complaint"]["suspect_upi_id"] == "kycupdate2026@ybl"
    assert packet["evidence_ledger"]["chain_verified"] is True
    assert packet["evidence_ledger"]["head_hash"]
    assert len(packet["automated_findings"]) == 2
    assert packet["where_to_report"]
    assert "did not submit" in packet["disclaimer"]


def test_packet_reports_a_broken_chain_instead_of_hiding_it():
    """A packet that quietly omitted tampering would be evidence laundering."""
    seed(3)
    records = read_all()
    records[1]["payload"]["verdict"] = "safe"
    rewrite(records)

    packet = build_packet(ComplaintDetails())
    assert packet["evidence_ledger"]["chain_verified"] is False
    assert packet["evidence_ledger"]["broken_at_seq"] == 2


def test_packet_names_its_data_sources():
    seed(1)
    packet = build_packet(ComplaintDetails())
    assert any("Google" in line for line in packet["data_sources"])
