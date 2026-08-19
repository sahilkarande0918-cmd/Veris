"""Naive detector vs Veris, on the same inputs.

    python scripts/demo_adversarial.py

The naive detector is the one almost every hackathon ships: "does the URL
contain a known bank's domain?" It is not a straw man -- substring matching
against a brand list is genuinely what a weekend project does, and it is
wrong in both directions at once.

Runs fully offline against the local fixtures. No network, no model.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "verdict-engine"))

os.environ["VERIS_OFFLINE"] = "1"

from app.checks import load_brands  # noqa: E402
from app.rules import decide  # noqa: E402
from app.checks import run_offline_checks  # noqa: E402
from app.subject import classify  # noqa: E402

BRAND_DOMAINS = [d for b in load_brands() for d in b["domains"]]

CASES = [
    ("https://xn--icicibnk-66g.com/login", "Cyrillic 'a' inside icicibank.com, shown as punycode", False),
    ("https://hdfcbank.com.secure-verify.top/login", "real brand domain as a subdomain of the attacker's", False),
    ("http://hdfcbank.com@secure-verify.top/login", "brand hidden in the URL userinfo, before the '@'", False),
    ("http://sbi.co.in.login-verify.icu/", "government bank domain as a subdomain label", False),
    ("http://192.168.1.50/sbi/netbanking", "bank login served from a raw IP", False),
    ("http://hdfcbnak.com/login", "two letters transposed", False),
    ("https://www.hdfcbank.com/", "the genuine article -- must NOT be flagged", True),
    ("https://irctc.co.in/", "genuine government site -- must NOT be flagged", True),
    ("https://bankofmaharashtra.in/", "a REAL bank absent from our brand list -- must NOT be flagged", True),
]


def naive_verdict(url: str) -> str:
    """The detector everyone else ships: substring match on a brand list."""
    lowered = url.lower()
    return "safe (brand recognised)" if any(d in lowered for d in BRAND_DOMAINS) else "scam"


def veris_verdict(raw: str) -> tuple[str, int, list]:
    subject = classify(raw)
    signals = run_offline_checks(subject.type, subject.value)
    verdict, score, _ = decide(signals)
    return verdict, score, signals


def main() -> int:
    print("=" * 78)
    print("NAIVE DETECTOR vs VERIS".center(78))
    print("naive rule: 'if the URL contains a known bank domain, it must be that bank'".center(78))
    print("=" * 78)

    wrong_naive = 0
    wrong_veris = 0

    for url, note, genuine in CASES:
        naive = naive_verdict(url)
        verdict, score, signals = veris_verdict(url)

        naive_ok = (genuine and naive.startswith("safe")) or (not genuine and not naive.startswith("safe"))
        veris_ok = (genuine and verdict == "safe") or (not genuine and verdict != "safe")
        wrong_naive += not naive_ok
        wrong_veris += not veris_ok

        print(f"\n  {url}")
        print(f"  ({note})")
        print(f"    naive : {naive:26} {'OK' if naive_ok else '<-- WRONG'}")
        print(f"    Veris : {verdict + ' (' + str(score) + ')':26} {'OK' if veris_ok else '<-- WRONG'}")
        for signal in signals:
            if signal.weight:
                print(f"            +{signal.weight:<3} {signal.id}: {signal.source}")

    total = len(CASES)
    print("\n" + "=" * 78)
    print(f"  naive detector : {total - wrong_naive}/{total} correct")
    print(f"  Veris          : {total - wrong_veris}/{total} correct")
    print("=" * 78)
    print("""
  The naive detector fails in BOTH directions. It waves through every
  impersonation that merely contains the brand string, and it calls a real
  bank a scam for the crime of not being on its list.

  Veris decides on the registrable domain, the Unicode skeleton and the URL
  structure, and cites a source for each signal. Note the last case: Veris
  does not claim an unlisted bank is safe, it reports that nothing flagged
  it. Absence of evidence is reported as absence of evidence.
""")
    return 0 if wrong_veris == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
