"""Make a QR code for the app download link.

    python scripts/make_qr.py                       # defaults to the GitHub releases page
    python scripts/make_qr.py https://example.com   # any URL
    python scripts/make_qr.py --out poster.png https://example.com

Point a phone camera at the result and it opens the link. Useful on a demo
poster or a slide so judges and teammates can install the app without typing
anything.

Needs `qrcode[pil]`:  pip install "qrcode[pil]"
"""

import argparse
import sys
from pathlib import Path

DEFAULT_URL = "https://github.com/sahilkarande0918-cmd/Veris/releases/latest"
DEFAULT_OUT = Path(__file__).resolve().parents[1] / "docs" / "download-qr.png"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", default=DEFAULT_URL)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    try:
        import qrcode
    except ImportError:
        print('qrcode is not installed. Run:  pip install "qrcode[pil]"', file=sys.stderr)
        return 1

    # High error correction: a printed poster gets creased, and a phone should
    # still read it from an angle across a room.
    code = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=12,
        border=4,
    )
    code.add_data(args.url)
    code.make(fit=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    code.make_image(fill_color="black", back_color="white").save(args.out)

    print(f"QR written to {args.out}")
    print(f"  encodes: {args.url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
