"""Phase 5: APK static analysis. The app is never installed or run."""

from pathlib import Path

import pytest

from app.apk import analyze, sha256_of
from app.rules import decide

FIXTURE = Path(__file__).resolve().parents[3] / "fixtures" / "apk" / "fake_loan_app.apk"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("VERIS_OFFLINE", "1")


def test_fake_loan_app_is_caught_by_its_permissions_alone():
    signals, meta = analyze(FIXTURE)
    verdict, score, _ = decide(signals)

    assert verdict == "likely_scam"
    assert score == 100
    assert meta["package"] == "com.instant.rupee.loan"


def test_the_contacts_plus_sms_combination_is_called_out():
    """The extortion kit is worth more than the sum of its permissions."""
    signals, _ = analyze(FIXTURE)
    combos = [s for s in signals if s.id == "apk_permission_combination"]
    assert combos, "contacts+SMS pairing was not reported"
    assert any("fake-loan-app pattern" in s.value for s in combos)


def test_every_apk_signal_is_cited():
    signals, _ = analyze(FIXTURE)
    for signal in signals:
        assert signal.source and signal.value
        assert signal.observed_at.endswith("+00:00")


def test_hash_is_reported_but_is_not_evidence_of_wrongdoing():
    signals, meta = analyze(FIXTURE)
    hashes = [s for s in signals if s.id == "apk_sha256"]
    assert len(hashes) == 1
    assert hashes[0].weight == 0
    assert hashes[0].value == meta["sha256"] == sha256_of(FIXTURE)


def test_a_missing_file_raises_rather_than_guessing():
    with pytest.raises(FileNotFoundError):
        analyze(FIXTURE.parent / "does-not-exist.apk")


def test_a_non_apk_is_reported_as_unparseable_not_as_safe(tmp_path):
    junk = tmp_path / "notreally.apk"
    junk.write_bytes(b"this is not a zip archive")
    signals, meta = analyze(junk)

    assert any(s.id == "apk_unparseable" for s in signals)
    assert meta["package"] is None


def test_mobsf_is_optional_and_absent_offline():
    signals, _ = analyze(FIXTURE)
    assert not [s for s in signals if s.id.startswith("mobsf")]
