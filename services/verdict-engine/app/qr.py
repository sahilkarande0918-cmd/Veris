"""Decode a QR code, so a QR scam is checked like any other input.

QR-code scams are in the problem statement twice: a sticker pasted over a real
merchant's QR, or a "scan to receive your refund" image, sends money to the
attacker. The defence is simple and deterministic: decode what the QR actually
contains, then run it through the same engine as a pasted link or UPI id. The
QR is just another way to carry a URL, a UPI request, or text.

ponytail: OpenCV ships a QR detector, so no pyzbar (which needs a system zbar
DLL that is painful on Windows) and no new heavy dependency beyond opencv.
"""

from __future__ import annotations

import numpy as np

# UPI intent QRs are a URI: upi://pay?pa=<vpa>&pn=<name>&am=<amount>...
# The payee address (pa) is the thing that actually receives money.
import re
from urllib.parse import parse_qs, urlsplit

_UPI_PA = re.compile(r"[?&]pa=([^&]+)", re.IGNORECASE)


def decode_qr(image_bytes: bytes) -> str | None:
    """Return the text encoded in a QR image, or None if there is no QR.

    Never raises on a bad image -- a corrupt upload returns None, so the caller
    can say "no QR found" rather than crash.
    """
    import cv2  # imported lazily so the service starts without opencv present

    array = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(array, cv2.IMREAD_COLOR)
    if image is None:
        return None
    detector = cv2.QRCodeDetector()
    text, _points, _straight = detector.detectAndDecode(image)
    return text or None


def upi_payee(qr_text: str) -> str | None:
    """Pull the UPI payee address out of a `upi://pay?...` QR.

    This is what the engine should actually judge: the money goes to `pa`, not
    to the merchant name the QR claims (`pn`), which an attacker sets freely.
    """
    if not qr_text.lower().startswith("upi://"):
        return None
    # urlsplit keeps the query; parse the payee address out of it.
    query = parse_qs(urlsplit(qr_text).query)
    payee = query.get("pa") or query.get("PA")
    if payee:
        return payee[0].strip().lower()
    match = _UPI_PA.search(qr_text)
    return match.group(1).strip().lower() if match else None


def subject_from_qr(qr_text: str) -> str:
    """Turn decoded QR text into the string the engine should check.

    A UPI QR -> the payee VPA (what receives the money). Anything else -> the
    raw text, which the normal classifier splits into a URL / domain / etc.
    """
    return upi_payee(qr_text) or qr_text
