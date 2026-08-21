"""The national intel distribution endpoint (docs/SCALABILITY.md)."""

import os

os.environ["VERIS_OFFLINE"] = "1"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)


def test_intel_rules_serves_a_versioned_rules_file():
    body = client.get("/intel/rules").json()
    assert len(body["version"]) == 16  # sha256 prefix, stable per content
    # The rules are the same shape the phone bundles and reads.
    assert "reported_vpas" in body["rules"]
    assert "blocked_hosts" in body["rules"]
    assert "thresholds" in body["rules"]


def test_version_changes_only_when_the_rules_change():
    first = client.get("/intel/rules").json()["version"]
    second = client.get("/intel/rules").json()["version"]
    # Deterministic: identical content -> identical version. That is what lets a
    # phone skip a download when nothing changed.
    assert first == second


def test_a_reported_vpa_in_the_feed_is_one_a_device_would_act_on():
    rules = client.get("/intel/rules").json()["rules"]
    # The feed carries the actual identifiers, so pushing a new one downstream is
    # what makes every phone smarter without collecting anyone's messages.
    assert any("@" in vpa for vpa in rules["reported_vpas"])
