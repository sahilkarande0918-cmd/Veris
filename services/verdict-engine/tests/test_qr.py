"""QR-code scam coverage: decode the QR, judge what it carries."""

import io
import os

os.environ["VERIS_OFFLINE"] = "1"

import qrcode  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.qr import subject_from_qr, upi_payee  # noqa: E402

client = TestClient(app)


def qr_png(data: str) -> bytes:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_upi_qr_is_judged_on_the_payee_not_the_claimed_name():
    """A QR can claim any merchant name; the money goes to `pa`. We judge pa."""
    text = "upi://pay?pa=kycupdate2026@ybl&pn=SBI%20Refund&am=4999&cu=INR"
    assert upi_payee(text) == "kycupdate2026@ybl"
    assert subject_from_qr(text) == "kycupdate2026@ybl"


def test_scan_a_scam_upi_qr_end_to_end():
    png = qr_png("upi://pay?pa=kycupdate2026@ybl&pn=Refund&am=4999&cu=INR")
    response = client.post("/check/qr", files={"file": ("scam.png", png, "image/png")})
    assert response.status_code == 200
    body = response.json()
    assert body["subject"]["value"] == "kycupdate2026@ybl"
    assert body["verdict"] == "likely_scam"
    assert any(s["id"] == "upi_reported" for s in body["signals"])


def test_scan_a_qr_carrying_a_homoglyph_link():
    png = qr_png("https://xn--icicibnk-66g.com/login")
    body = client.post("/check/qr", files={"file": ("x.png", png, "image/png")}).json()
    assert body["verdict"] == "likely_scam"
    assert any(s["id"] == "homoglyph_impersonation" for s in body["signals"])


def test_a_clean_upi_qr_is_not_flagged():
    png = qr_png("upi://pay?pa=merchant.store@ybl&pn=Chai%20Shop&am=20&cu=INR")
    body = client.post("/check/qr", files={"file": ("ok.png", png, "image/png")}).json()
    assert body["subject"]["value"] == "merchant.store@ybl"
    assert body["verdict"] == "safe"


def test_an_image_with_no_qr_is_a_clean_422():
    # A 1x1 PNG: valid image, no QR. Should be a clear error, not a crash.
    png = qr_png("x")[:20] + b"junk"
    response = client.post("/check/qr", files={"file": ("bad.png", png, "image/png")})
    assert response.status_code == 422
