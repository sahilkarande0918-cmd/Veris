"""API auth + rate limiting (Tier 2 #7).

Auth is opt-in: open when VERIS_AUTH_SECRET is unset (offline/LAN/demo), enforced
when it is set (a public host). Rate limits always apply.
"""

from fastapi.testclient import TestClient

from app import security
from app.main import app

client = TestClient(app)


def test_open_when_no_secret(monkeypatch):
    monkeypatch.delenv("VERIS_AUTH_SECRET", raising=False)
    assert not security.auth_enabled()
    # No Authorization header, still works.
    assert client.post("/check", json={"input": "hdfcbank.com"}).status_code == 200


def test_register_returns_token(monkeypatch):
    monkeypatch.setenv("VERIS_AUTH_SECRET", "s3cret")
    r = client.post("/auth/device", json={"device_id": "device-abc123"})
    assert r.status_code == 200
    assert r.json()["auth_required"] is True
    assert r.json()["token"].startswith("device-abc123.")


def test_protected_requires_valid_token(monkeypatch):
    monkeypatch.setenv("VERIS_AUTH_SECRET", "s3cret")
    # No token -> 401.
    assert client.post("/check", json={"input": "hdfcbank.com"}).status_code == 401
    # Forged token -> 401.
    bad = {"Authorization": "Bearer device-abc123.deadbeef"}
    assert client.post("/check", json={"input": "hdfcbank.com"}, headers=bad).status_code == 401
    # Minted token -> 200.
    token = client.post("/auth/device", json={"device_id": "device-abc123"}).json()["token"]
    good = {"Authorization": f"Bearer {token}"}
    assert client.post("/check", json={"input": "hdfcbank.com"}, headers=good).status_code == 200


def test_health_and_register_stay_open(monkeypatch):
    monkeypatch.setenv("VERIS_AUTH_SECRET", "s3cret")
    assert client.get("/health").status_code == 200
    assert client.post("/auth/device", json={"device_id": "device-xyz999"}).status_code == 200


def test_ip_ceiling_closes_token_minting_bypass(monkeypatch):
    # Pentest F2: minting many tokens must not multiply the allowance.
    monkeypatch.setenv("VERIS_AUTH_SECRET", "s3cret")
    limit, _ = security.LIMITS["_ip_total"]
    codes = [client.post("/auth/device", json={"device_id": f"mint-{i}-xxxxxxxx"}).status_code for i in range(limit)]
    assert all(c == 200 for c in codes)
    # The IP is now at its ceiling; further requests are refused regardless of endpoint.
    assert client.post("/auth/device", json={"device_id": "mint-over-xxxxxxxx"}).status_code == 429
    # A brand-new, validly-signed token cannot escape the exhausted IP ceiling.
    tok = security.mint_token("escape-dev-xxxxxxxx")
    assert client.post("/check", json={"input": "x.test"}, headers={"Authorization": f"Bearer {tok}"}).status_code == 429


def test_rate_limit_returns_429(monkeypatch):
    monkeypatch.delenv("VERIS_AUTH_SECRET", raising=False)
    limit, _ = security.LIMITS["/check"]
    ok = sum(client.post("/check", json={"input": "hdfcbank.com"}).status_code == 200 for _ in range(limit))
    assert ok == limit
    # The next one over the limit is refused.
    assert client.post("/check", json={"input": "hdfcbank.com"}).status_code == 429
