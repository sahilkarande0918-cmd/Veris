"""The tamper-detection demo, start to finish, in one command.

    python scripts/demo_ledger.py

Records three incidents, exports an NCRP-aligned packet, then edits a verdict
in the log the way a bad actor would and shows the chain catching it. Runs
fully offline against a throwaway ledger, so it never touches real data and
never needs the network.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "verdict-engine"))

os.environ["VERIS_OFFLINE"] = "1"
os.environ.setdefault("VERIS_LEDGER_PATH", str(Path(tempfile.mkdtemp()) / "demo_ledger.jsonl"))

from app.ledger import compute_hash, ledger_path, read_all, verify  # noqa: E402
from app.main import app  # noqa: E402
from app.packet import ComplaintDetails, build_packet  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)

SUSPECTS = [
    "https://xn--icicibnk-66g.com/login",
    "http://sbi-kyc-verify-online.top/login",
    "kycupdate2026@ybl",
]


def rule(title: str) -> None:
    print(f"\n{'=' * 68}\n{title}\n{'=' * 68}")


def save(records: list[dict]) -> None:
    """Write the log back out, exactly as a tamperer with file access would."""
    ledger_path().write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8"
    )


def main() -> int:
    rule("1. Three incidents are checked and recorded")
    for suspect in SUSPECTS:
        result = client.post("/check", json={"input": suspect, "explain": False}).json()
        print(f"  {result['verdict']:<12} score {result['score']:>3}  {suspect}")

    rule("2. The chain is intact")
    status = verify()
    print(f"  verified : {status['ok']}")
    print(f"  records  : {status['count']}")
    print(f"  head     : {status['head_hash'][:32]}...")
    print(f"  signature: {status['head_signature'][:32]}...")
    print(f"  {status['reason']}")

    rule("3. An NCRP-aligned complaint packet is exported")
    complaint = ComplaintDetails(
        incident_datetime="2026-08-18T10:30:00+05:30",
        amount_lost=45000.0,
        payment_mode="UPI",
        suspect_upi_id="kycupdate2026@ybl",
        suspect_bank_or_wallet="PhonePe",
        transaction_reference="UTR123456789",
        suspect_urls=[SUSPECTS[0], SUSPECTS[1]],
        description="SMS claimed KYC expiry; paid via UPI to the id above.",
    )
    packet = build_packet(complaint)
    print(f"  amount lost      : Rs {packet['complaint']['amount_lost']:,.0f}")
    print(f"  suspect UPI id   : {packet['complaint']['suspect_upi_id']}")
    print(f"  findings attached: {len(packet['automated_findings'])}")
    print(f"  chain verified   : {packet['evidence_ledger']['chain_verified']}")
    print(f"  file the report  : {packet['where_to_report'][0]['url']}")

    rule("4. Someone edits the log to make a scam look safe")
    records = read_all()
    target = records[1]
    print(f"  record #{target['seq']} was: verdict={target['payload']['verdict']}")
    target["payload"]["verdict"] = "safe"
    target["payload"]["score"] = 0
    # A careless attacker stops here. A careful one also recomputes the hash --
    # step 5 catches both.
    save(records)
    print(f"  record #{target['seq']} now: verdict={target['payload']['verdict']}  <-- tampered")

    rule("5. The chain catches it, and says exactly where")
    status = verify()
    print(f"  verified  : {status['ok']}")
    print(f"  broken at : record #{status['broken_at']}")
    print(f"  reason    : {status['reason']}")

    rule("6. Even if the attacker recomputes that record's own hash")
    target["hash"] = compute_hash(target)
    save(records)
    status = verify()
    print(f"  verified  : {status['ok']}")
    print(f"  broken at : record #{status['broken_at']}")
    print(f"  reason    : {status['reason']}")
    print("\n  The next record still points at the original hash. To hide the edit")
    print("  they must rewrite every record after it -- and then the signed head")
    print("  no longer matches.\n")

    return 0 if not status["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
