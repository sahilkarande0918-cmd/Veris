"""Input-validation / DoS-limit hardening (Tier 1 #3).

These are the boundary checks: the engine must refuse oversized or malformed
input with a clean error, never crash or buffer an unbounded upload.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import MAX_APK_BYTES, MAX_IMAGE_BYTES, MAX_INPUT_CHARS, app
from app.packet import ComplaintDetails

client = TestClient(app)


def test_oversized_input_is_rejected():
    resp = client.post("/check", json={"input": "a" * (MAX_INPUT_CHARS + 1)})
    assert resp.status_code == 422


def test_empty_input_is_rejected():
    assert client.post("/check", json={"input": ""}).status_code == 422


def test_unknown_language_is_rejected_at_the_boundary():
    resp = client.post("/check", json={"input": "hdfc.com", "language": "klingon"})
    assert resp.status_code == 422


def test_oversized_qr_image_is_rejected():
    huge = b"\x89PNG\r\n" + b"0" * (MAX_IMAGE_BYTES + 1)
    resp = client.post("/check/qr", files={"file": ("big.png", huge, "image/png")})
    assert resp.status_code == 413


def test_non_image_upload_to_qr_is_rejected():
    resp = client.post("/check/qr", files={"file": ("x.exe", b"MZ...", "application/x-msdownload")})
    assert resp.status_code == 422


def test_non_apk_upload_is_rejected():
    resp = client.post("/check/apk", files={"file": ("notreally.txt", b"hello", "text/plain")})
    assert resp.status_code == 422


def test_apk_cap_is_a_sane_ceiling():
    # A guard, not a scan: the cap should admit a real APK but not gigabytes.
    assert 50 * 1024 * 1024 < MAX_APK_BYTES <= 512 * 1024 * 1024


def test_complaint_fields_are_length_bounded():
    with pytest.raises(ValidationError):
        ComplaintDetails(description="x" * 5001)
    with pytest.raises(ValidationError):
        ComplaintDetails(suspect_urls=["http://x/" + "a" * 3000])
