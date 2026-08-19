"""The whole Veris demo, offline, in one command. [Phase 7]

    python scripts/demo_all.py

Runs every claim the pitch makes, with the network off, against a throwaway
ledger. If this exits 0 on a cold machine, the demo works.

Order matches the 90-second script in docs/DEMO_SCRIPT.md:
  1. catch what a naive detector misses
  2. show the evidence behind the verdict
  3. explain it in Marathi
  4. analyse a fake loan APK
  5. prove the evidence log detects tampering
  6. export an NCRP-aligned complaint packet
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "verdict-engine"))

os.environ["VERIS_OFFLINE"] = "1"
os.environ["VERIS_LEDGER_PATH"] = str(Path(tempfile.mkdtemp()) / "demo.jsonl")

from app.apk import analyze as analyze_apk  # noqa: E402
from app.ledger import compute_hash, ledger_path, read_all, verify  # noqa: E402
from app.main import app  # noqa: E402
from app.packet import ComplaintDetails, build_packet  # noqa: E402
from app.rules import decide  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)
failures: list[str] = []


def step(number: int, title: str) -> None:
    print(f"\n{'=' * 74}\n  {number}. {title}\n{'=' * 74}")


def expect(condition: bool, description: str) -> None:
    print(f"     {'PASS' if condition else 'FAIL'}  {description}")
    if not condition:
        failures.append(description)


def main() -> int:
    print("VERIS -- full offline demo (VERIS_OFFLINE=1, throwaway ledger)")

    # 1 -------------------------------------------------------------------
    step(1, "The homoglyph a naive detector cannot see")
    attack = "https://xn--icicibnk-66g.com/login"
    result = client.post("/check", json={"input": attack, "language": "mr"}).json()
    print(f"     input   : {attack}")
    print(f"     verdict : {result['verdict']} (score {result['score']})")
    expect(result["verdict"] == "likely_scam", "Cyrillic lookalike of icicibank.com is caught")

    # 2 -------------------------------------------------------------------
    step(2, "Every signal names its source")
    for signal in result["signals"]:
        print(f"     +{signal['weight']:<3} {signal['id']}")
        print(f"          {signal['source']}")
    expect(all(s["source"] and s["observed_at"] for s in result["signals"]),
           "every signal carries {source, value, observed_at}")
    expect(bool(result["rules_fired"]), "the exact rules that fired are returned")

    # 3 -------------------------------------------------------------------
    step(3, "Explained in plain language, without deciding anything")
    explanation = result["explanation"]
    print(f"     via : {explanation['generated_by']}")
    print(f"     EN  : {explanation['english'][:150]}")
    print(f"     MR  : {explanation['regional'][:150]}")
    expect("verdict" not in explanation, "the explanation type has no verdict field")
    expect(any("ऀ" <= c <= "ॿ" for c in explanation["regional"]),
           "regional text is real Devanagari, not English")

    # 4 -------------------------------------------------------------------
    step(4, "A fake loan app, judged on its manifest alone")
    apk = ROOT / "fixtures" / "apk" / "fake_loan_app.apk"
    signals, meta = analyze_apk(apk)
    verdict, score, _ = decide(signals)
    print(f"     package : {meta['package']}")
    print(f"     verdict : {verdict} (score {score}), {meta['dangerous_count']} risky permissions")
    combo = next((s for s in signals if s.id == "apk_permission_combination"), None)
    print(f"     key     : {combo.value[:110] if combo else 'none'}")
    expect(verdict == "likely_scam", "fake loan app is caught without installing it")

    # 5 -------------------------------------------------------------------
    step(5, "The evidence log detects tampering")
    client.post("/check", json={"input": "kycupdate2026@ybl", "explain": False})
    before = verify()
    print(f"     chain   : {before['count']} records, verified={before['ok']}")
    expect(before["ok"], "chain is intact before tampering")

    records = read_all()
    records[0]["payload"]["verdict"] = "safe"
    records[0]["hash"] = compute_hash(records[0])  # the careful attacker
    ledger_path().write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8"
    )
    after = verify()
    print(f"     tampered: verified={after['ok']}, broken at record #{after['broken_at']}")
    print(f"     reason  : {after['reason'][:100]}")
    expect(not after["ok"], "tampering is detected even after the hash is recomputed")

    # 6 -------------------------------------------------------------------
    step(6, "An NCRP-aligned complaint packet")
    packet = build_packet(ComplaintDetails(
        incident_datetime="2026-08-20T10:30:00+05:30",
        amount_lost=45000.0, payment_mode="UPI",
        suspect_upi_id="kycupdate2026@ybl", suspect_urls=[attack],
        description="SMS claimed KYC expiry; paid via UPI.",
    ))
    ledger = packet["evidence_ledger"]
    print(f"     amount        : Rs {packet['complaint']['amount_lost']:,.0f}")
    print(f"     findings      : {len(packet['automated_findings'])}")
    print(f"     chain_verified: {ledger['chain_verified']}  (broken at #{ledger['broken_at_seq']})")
    print(f"     file at       : {packet['where_to_report'][0]['url']}")
    expect(ledger["chain_verified"] is False,
           "the packet REPORTS the broken chain instead of hiding it")
    expect("did not submit" in packet["disclaimer"], "packet states Veris filed nothing")

    # ---------------------------------------------------------------------
    print(f"\n{'=' * 74}")
    if failures:
        print(f"  {len(failures)} CHECK(S) FAILED:")
        for item in failures:
            print(f"    - {item}")
        return 1
    print("  ALL CHECKS PASSED -- the full demo runs with the network off.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
