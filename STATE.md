# Veris — project state (detailed)

_Last updated: 2026-08-22. Single source of truth if context is lost. Read this
first, then `docs/PROBLEM_COVERAGE.md` and `docs/COMPETITIVE_ANALYSIS.md`._

Veris = verifiable digital-fraud detection + tamper-evident incident reporting,
for Smart India Hackathon 2026 ("AI-Assisted Digital Fraud Detection and
Verifiable Cyber Incident Reporting").

**The rule that governs everything:** the verdict is produced by deterministic
checks against real sources. The LLM only explains the evidence; it never
decides the verdict.

## Where the project lives

- Working copy: `C:\dev\Veris` (moved out of OneDrive, which corrupts native
  builds by dehydrating .so files).
- GitHub: https://github.com/sahilkarande0918-cmd/Veris (branch `main`, pushed).
- Old OneDrive copy `C:\Users\Sahil\OneDrive\Desktop\Veris` is stale — ignore.

## What is BUILT and VERIFIED (working)

### Backend — verdict engine (`services/verdict-engine`, Python/FastAPI)
- Deterministic checks, all offline-capable: blocklists (PhishTank/URLhaus/
  OpenPhish snapshots), homoglyph (Unicode UTS #39), brand-as-subdomain (PSL),
  typosquat (Levenshtein), userinfo-deception, IP-host, UPI VPA format +
  reported list.
- Online enrichment (optional, cached, never required): Safe Browsing,
  VirusTotal, RDAP age, live TLS cert.
- Explanation layer: Groq `openai/gpt-oss-120b` writes EN + Marathi/Hindi prose
  from the evidence; three guards (no verdict field, contradiction, invented-
  source); templated offline fallback. LLM never decides.
- Tamper-evident ledger: SHA-256 hash chain, `/ledger/verify` names the first
  broken record. NCRP/1930-aligned complaint packet export.
- QR: `/check/qr` decodes an image (OpenCV) OR takes decoded text; a UPI QR is
  judged on the payee (`pa`), not the claimed name.
- National intel: `/intel/rules` serves the signed rules file with a version
  hash (the "push to every phone" pathway; see docs/SCALABILITY.md).
- Demo-only (guarded by `VERIS_DEMO=1`): `/ledger/dev/tamper` and
  `/ledger/dev/rebuild` for the live tamper demo.
- **~108 tests passing.** Run: `cd services/verdict-engine && .venv/Scripts/python -m pytest -q`
- Metrics: `python scripts/benchmark.py` → 100% accuracy, 0% FP, 0.08ms median
  on the fixture set.

### Mobile app (`apps/mobile`, Expo SDK 57 / React Native / TypeScript)
Package `in.veris.app`. Screens: Home, Result, Report, Ledger (History),
Protection, Scan.
- **Share-sheet intake** (link/text/image) — verified on device.
- **QR camera scanner** (`scan.tsx`, expo-camera) — decodes on-device, runs
  through `/check/qr`. Verified on device.
- **Screenshot OCR** (expo-text-extractor / ML Kit, on-device) — "Check a
  screenshot" button + share-sheet. Extracts URL/UPI/phone → engine. Verified.
- **Notification guard** (`plugins/withNotificationGuard.js`,
  NotificationListenerService) — auto-warns on scam SMS/WhatsApp/email with NO
  READ_SMS. On-device, nothing transmitted. Verified catching a scam at 100.
- **Call screening** (`plugins/withCallScreening.js`, CallScreeningService) —
  built; role grant depends on the OEM dialler.
- **On-device triage** (`ondevice.ts`) — verdict with no server, offline.
- **Evidence-integrity UI** (History) — "Verify evidence integrity" green/red;
  dev-only "Break the chain"/"Restore". Verified green→red→green on device.
- **In-app Engine URL** (Protection) — paste any engine address; one APK works
  on any network. Falls back to on-device triage if unreachable.
- **In-app update banner** — checks GitHub Releases on launch.

## Signing, release, distribution

- Release keystore: `apps/mobile/credentials/veris-release.keystore` (RSA 4096),
  gitignored. **Backed up to** `C:\Users\Sahil\OneDrive\Documents\Veris-Signing-Backup\`.
  Wired via `plugins/withReleaseSigning.js` (survives prebuild).
- Release APK is standalone (JS bundle baked in) — opens with no laptop/Metro.
- v0.1.0 published: https://github.com/sahilkarande0918-cmd/Veris/releases
- QR to download: `docs/download-qr.png` (points at releases/latest).
- Install guide: `docs/INSTALL.md`.

## The hosting question (open decision)

App must "work on any internet." App OPENS standalone anywhere; on-device
features (QR/OCR/notification guard/call screen/offline triage) work anywhere
with no engine. The FULL engine (server verdict, ledger, tamper demo, LLM)
needs a reachable engine:
- **Same Wi-Fi as laptop:** run engine `--host 0.0.0.0 --port 8010`, paste
  `http://<laptop-ip>:8010` in the app's Engine URL. No cost.
- **Anywhere (mobile data):** needs a public host. **Hugging Face Docker
  Spaces now require PRO (not free).** Render free tier is the recommended free
  host — `render.yaml` + `Dockerfile` are ready; needs a one-time GitHub
  connect by the user (I cannot auth their host account). Cold-starts after
  idle.

## Known cleanups / to-do
- **RECORD_AUDIO** permission crept into the release manifest from expo-camera;
  strip via `android.blockedPermissions` in app.json (we only scan QR).
- Debug builds need Metro (laptop) to launch — expected; use the RELEASE APK.
- Groq key not set on any cloud engine yet (would enable LLM explanations
  server-side; template fallback works without it).
- Fallback demo VIDEO not recorded (only the user can do this).
- Screenshot OCR extracts text but the packet's screenshot-hash is separate
  (both intact; no OCR-of-screenshot-into-packet linkage — roadmap).

## The demo (90-second script) — TODO to write to docs/DEMO_SCRIPT.md
1. QR scam catch (scan a homoglyph-URL QR → likely_scam + cited signal).
2. Forwarded-screenshot catch (share a fake-payment SMS screenshot → verdict).
3. Homoglyph/punycode domain catch (paste `https://xn--icicibnk-66g.com/login`).
4. Evidence integrity: green → Break the chain → red (record named) → Restore.
5. One-tap evidence packet → 1930 / cybercrime.gov.in deep-link.

## Scope status
The user's 3 final tasks are DONE (QR scanner, screenshot OCR, visible tamper
check). Per instruction: STOP adding features; finish demo hardening
(offline dry-run, confirm LLM-only-explains, this STATE.md, demo script).
Then hosting decision + final APK.

## Key gotchas (will bite again)
- OneDrive dehydrates NDK/.so files → native build fails "Cannot snapshot". Fix:
  `scripts/fix_cloud_placeholders.ps1`, or stay in `C:\dev`.
- `expo run:android` skips prebuild if `android/` exists → app.json changes need
  `npx expo prebuild --clean -p android`.
- Debug app "stuck on logo" = Metro not reached; relaunch pointing at
  `127.0.0.1:8081` over `adb reverse`. Release APK never has this.
- `in` is a Kotlin keyword; package `in.veris.app` needs escaping (handled in
  the config plugins).
- Kill stray Gradle/Node daemons if builds crawl (`Get-Process java|node`).
- Release builds: exclude lint (`-x lintVitalRelease`), arm64 only, `--no-daemon`.
