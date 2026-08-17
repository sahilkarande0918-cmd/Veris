"""Phase 1 acceptance: 10 known-bad and 10 known-good, with the network OFF.

`VERIS_OFFLINE=1` is set before the app is imported, so any accidental
network call in the verdict path fails this suite rather than passing quietly
on a machine that happens to have wifi.
"""

import json
import os
from pathlib import Path

import pytest

os.environ["VERIS_OFFLINE"] = "1"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)

SAMPLES = json.loads(
    (Path(__file__).resolve().parents[3] / "fixtures" / "samples.json").read_text(
        encoding="utf-8"
    )
)


def _check(raw: str) -> dict:
    response = client.post("/check", json={"input": raw})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("case", SAMPLES["bad"], ids=lambda c: c["input"][:45])
def test_known_bad_is_caught(case):
    result = _check(case["input"])
    assert result["verdict"] == case["expect"], (
        f"{case['input']} -> {result['verdict']}, expected {case['expect']} "
        f"({case['why']}); rules fired: {result['rules_fired']}"
    )
    # A verdict nobody can audit is worthless: demand the citation.
    assert result["signals"], "a bad verdict with no signals is unciteable"
    assert result["rules_fired"]


@pytest.mark.parametrize("case", SAMPLES["good"], ids=lambda c: c["input"][:45])
def test_known_good_is_not_flagged(case):
    result = _check(case["input"])
    assert result["verdict"] == case["expect"], (
        f"{case['input']} -> {result['verdict']}, expected {case['expect']} "
        f"({case['why']}); rules fired: {result['rules_fired']}"
    )


def test_every_signal_carries_its_citation():
    """The core promise: source + value + timestamp on every signal."""
    for case in SAMPLES["bad"]:
        for signal in _check(case["input"])["signals"]:
            assert signal["source"], f"uncited signal in {case['input']}"
            assert signal["value"]
            assert signal["observed_at"].endswith("+00:00")


def test_no_network_calls_happen_offline(monkeypatch):
    """Offline mode must not merely tolerate the network -- it must not try."""
    import httpx

    def explode(*args, **kwargs):
        raise AssertionError("verdict path attempted a network call while offline")

    monkeypatch.setattr(httpx, "get", explode)
    monkeypatch.setattr(httpx, "post", explode)
    for case in SAMPLES["bad"] + SAMPLES["good"]:
        _check(case["input"])
