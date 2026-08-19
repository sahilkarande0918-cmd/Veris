"""APK static analysis, side by side. [Phase 5]

    python scripts/demo_apk.py

Analyses a fake loan app and Veris itself with the same code, so the contrast
is the evidence rather than the framing. Neither app is installed or run --
this reads the manifest out of the APK, which is exactly what a victim cannot
do before tapping Install.

Offline. No MobSF, no container, no network.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "verdict-engine"))
os.environ["VERIS_OFFLINE"] = "1"

from app.apk import analyze  # noqa: E402
from app.rules import decide  # noqa: E402

TARGETS = [
    (ROOT / "fixtures" / "apk" / "fake_loan_app.apk", "a fake instant-loan app"),
    (
        ROOT / "apps" / "mobile" / "android" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk",
        "Veris itself (debug build), analysed by its own rules",
    ),
]


def main() -> int:
    for path, label in TARGETS:
        print("=" * 76)
        if not path.exists():
            print(f"  SKIP {label}: not built yet ({path.name})")
            continue

        signals, meta = analyze(path)
        verdict, score, _ = decide(signals)

        print(f"  {label}")
        print(f"  package : {meta['package']}  v{meta.get('version')}")
        print(f"  sha256  : {meta['sha256'][:48]}...")
        print(f"  verdict : {verdict.upper()}  (score {score}/100)")
        print(f"  {meta['dangerous_count']} permission(s) of fraud interest:")
        for signal in signals:
            if signal.weight:
                print(f"     +{signal.weight:<3} {signal.value}")
        if not meta["dangerous_count"]:
            print("     (none)")
        print()

    print("=" * 76)
    print("""
  Nothing here is a model's opinion. A permission list is a fact declared in
  the manifest, and the verdict is those facts weighted by published rules.
  The pairing that matters is contacts + SMS: harvest the victim's contact
  list, intercept the bank OTP, then threaten to message everyone they know.

  Veris scores itself too, and does not score zero -- its debug build carries
  SYSTEM_ALERT_WINDOW from React Native's dev overlay. A tool that exempted
  itself from its own rules would not be worth trusting.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
