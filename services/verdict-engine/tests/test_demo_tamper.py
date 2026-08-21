"""The dev-only tamper demo endpoints: gated, and they do what the stage needs."""

import json
import os

os.environ["VERIS_OFFLINE"] = "1"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.ledger import append, ledger_path, verify  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)


def seed(n: int = 3) -> None:
    for i in range(n):
        append("check", {"subject": {"value": f"http://x{i}.test"}, "verdict": "likely_scam", "score": 70})


def test_tamper_endpoints_are_hidden_unless_demo_is_on(monkeypatch):
    monkeypatch.delenv("VERIS_DEMO", raising=False)
    assert client.post("/ledger/dev/tamper").status_code == 404
    assert client.post("/ledger/dev/rebuild").status_code == 404


def test_tamper_breaks_the_chain_and_rebuild_heals_it(monkeypatch):
    monkeypatch.setenv("VERIS_DEMO", "1")
    seed(3)
    assert verify()["ok"] is True

    tampered = client.post("/ledger/dev/tamper").json()
    assert tampered["tampered"] is True
    broken = verify()
    assert broken["ok"] is False
    assert broken["broken_at"] == tampered["seq"]  # names the exact record

    client.post("/ledger/dev/rebuild")
    assert verify()["ok"] is True  # repeatable for the next demo run


def test_tamper_breaks_even_a_record_that_is_already_safe(monkeypatch):
    """Regression: if the edited record already read 'safe', a naive tamper that
    just sets verdict='safe' changes nothing and the chain stays valid."""
    monkeypatch.setenv("VERIS_DEMO", "1")
    for i in range(3):
        append("check", {"subject": {"value": f"http://ok{i}.test"}, "verdict": "safe", "score": 0})
    assert verify()["ok"] is True
    client.post("/ledger/dev/tamper")
    assert verify()["ok"] is False  # must be detected despite the record being 'safe'


def test_tamper_needs_at_least_two_records(monkeypatch):
    monkeypatch.setenv("VERIS_DEMO", "1")
    append("check", {"subject": {"value": "http://only.test"}, "verdict": "safe"})
    assert client.post("/ledger/dev/tamper").json()["tampered"] is False
