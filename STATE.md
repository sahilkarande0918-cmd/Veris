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

## Hosting — DEPLOYED (2026-08-24)

**Live engine: `https://veris-engine.onrender.com`** (Render free tier, Docker
Blueprint `render.yaml`, `VERIS_DEMO=1`). Verified end-to-end on the public URL:
`/health`, `/check`, `/check/email` (full forensics), `/email/campaign` (4→1
campaign), `/privacy/policy`, and the tamper demo (break→rebuild→green). Idle RSS
~180 MB (fits the 512 MB free tier). Cold-starts ~50 s after 15 min idle — add an
UptimeRobot HTTP monitor on `/health` every 5 min to keep it warm. Ledger is
ephemeral (resets on redeploy) — fine for the live tamper demo. `.dockerignore`
keeps the local `.venv`/caches out of the 1.2 GB image.
Point the app at it: Protection → Engine URL → `https://veris-engine.onrender.com` → Save.

## The hosting question (earlier open decision — now resolved above)

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

## Security hardening (Tier 1 + Tier 2 applied 2026-08-22)

Loop-engineered pass. **No verdict-engine logic, demo flow, or working feature
changed.** Verdict is still deterministic; the LLM still only explains
(`rules.py`/`explain.py`/`checks.py`/`enrich.py` untouched — verified by diff).

**Durability proven:** `npx expo prebuild --clean -p android` reproduces the
entire hardening posture from tracked config (config plugins + app.json +
expo-build-properties) — HTTPS/NSC, taskAffinity, allowBackup, R8, proguard
keeps, secure-store backup exclusion. `android/` stays gitignored.

**Applied (Tier 1):**
- **No client secrets.** Grepped source, `app.json`, `.env`, and the built
  release bundle — zero API keys in the client. Architecture already
  client→backend→third-party; Groq/VirusTotal/Safe Browsing keys are
  backend-only. MobSF confirms 0 secrets.
- **HTTPS-only (strict, hosted-only).** `usesCleartextTraffic=false` +
  `network_security_config.xml` forbidding cleartext to **all** hosts, via
  `plugins/withHttpsOnly.js` (survives prebuild) and the committed manifest.
  MobSF reports network config as **secure**. Consequence (accepted): the LAN
  `http://<laptop-ip>:8010` demo path no longer connects — the engine must be a
  hosted **HTTPS** URL; unreachable → on-device triage fallback. Protection
  screen hint + `.env` placeholder updated to https.
- **Backend input validation / DoS limits** (`app/main.py`, `app/packet.py`):
  input length cap, `language` restricted to `mr|hi|en`, upload size caps
  (10 MB image / 200 MB APK) via streaming read-cap, image content-type check,
  global Content-Length guard, complaint field/list caps. No shell/SQL anywhere
  (ledger is JSONL) — verified. New `tests/test_input_limits.py`; **113 tests
  pass**, all offline.
- **Least-privilege permissions.** Built APK declares only CAMERA, INTERNET,
  POST_NOTIFICATIONS (+ Expo ACCESS_NETWORK_STATE, AndroidX internal
  signature-perm). No SMS/CALL_LOG/RECEIVE_SMS/CONTACTS/RECORD_AUDIO.
- **`allowBackup=false`** (was true) — closes adb-backup data extraction.
- **`taskAffinity=""`** on application + MainActivity — task-hijacking mitigation.
- **R8/ProGuard on** (`minifyEnabled` + `shrinkResources`): APK 50 MB → 39 MB,
  70 MB mapping.txt confirms obfuscation. Durable across prebuild via
  `expo-build-properties` (app.json); keep-rules for `in.veris.app.**` +
  `expo.modules.**`.
- **MobSF v4.5.2 static scan** of the hardened release APK. Score **49/100**;
  report saved as `SECURITY_MobSF_report.json` + `.md`. All Tier-1-class
  findings (secrets, weak network config, dangerous perms, insecure storage)
  fixed. Remaining 3 HIGHs are accepted-with-rationale: minSdk=24 (Expo default,
  compat), StrandHogg 1.0/2.0 (keyed on `launchMode=singleTask`, which
  share-intent requires; `taskAffinity=""` mitigates the vector). See the report.

**Applied (Tier 2):**
- **#7 API auth + rate limiting** (`app/security.py`). Opt-in, offline-first:
  unset `VERIS_AUTH_SECRET` → engine open (LAN/offline/tests); set it on a public
  host → `/check` + `/ledger` require a per-device bearer token minted at
  `/auth/device` (stateless HMAC, no DB). In-process sliding-window rate limiter,
  per endpoint, keyed by device (or IP when open). Client (`api.ts`) registers +
  attaches the token at the one `request()` choke point; 401 re-registers once.
  118 backend tests pass.
- **#8 at-rest, client Keystore** (`api.ts` → `expo-secure-store`). engineUrl,
  deviceId, and the API token now live in the Android Keystore-backed store, not
  plaintext AsyncStorage. The evidence **ledger is server-side and already
  tamper-evident** — `/ledger/verify` + packet export are unchanged (app persists
  nothing else sensitive: History is fetched live).
- **#9 cert pinning, OFF by default** (`plugins/withHttpsOnly.js` +
  `docs/CERT_PINNING.md`). Set `extra.enginePinHost` + `extra.enginePins` in
  app.json → the NSC pins that host; empty → no pinning, so a bad pin can never
  brick the demo unless deliberately enabled + device-tested.

**Applied (Tier 3):**
- **#10 FLAG_SECURE** on the evidence (History) + report screens via
  `expo-screen-capture` (`src/lib/secureScreen.ts`). **OFF by default**
  (`extra.secureScreens: false`) because FLAG_SECURE also blacks the screen out
  in screen recordings and projector mirroring — which would sabotage the demo
  (History tamper-check is demo step 4). Set `extra.secureScreens: true` +
  prebuild for a real deployment; then screenshots/recording of those two
  screens are blocked.

**Backend penetration test (AI-assisted + manual, 2026-08-22):**
Strix (`strix-agent`) was fully set up (Docker sandbox pulled, target reachable)
but couldn't run — Anthropic key had no credits, Groq is incompatible with
Strix's tool schemas. A manual pentest of the same scope (`SECURITY_Strix_report.md`)
found and **fixed** two issues, verified by re-test + the suite:
- **F1 SSRF** (enrich.py dialled attacker-chosen hosts via the TLS-cert fetch) —
  fixed: `_safe_ip()` refuses non-global IPs and pins the connection (anti-rebinding).
- **F2 rate-limit bypass** (unlimited `/auth/device` token minting reset the
  quota) — fixed: per-IP ceiling across all endpoints.
- **F3 ledger not access-scoped** (any device reads the full log) — accepted +
  documented as single-tenant; a real fix would alter `/ledger/verify` + the demo.
- Not exploitable: injection (no SQL/shell), mass-assignment (verdict computed
  server-side — the core rule held under attack), file upload (capped, fixed temp
  name). 123 backend tests pass.

**Roadmap (Tier 3 — deliberately not implemented here):**
- **#11 Play Integrity root/tamper detection.** Real Play Integrity needs a Play
  Console app + a Cloud project with the Integrity API + a backend endpoint that
  verifies Google's signed verdict. It returns UNEVALUATED/failing on a
  sideloaded APK and on emulators/rooted devices — i.e. it cannot function on
  our demo device, and a local root-check stand-in would be bypassable theater.
  Plan when productionised: client `IntegrityManager` → nonce from a new
  `/integrity/nonce` endpoint → verify the token server-side → **warn-only**
  banner, never block. Deferred until the app ships through Play.
- **#12 deeper RASP / attestation** — note only; out of scope for the demo.
- Optional: raise `minSdkVersion` to 26/28 to clear the MobSF minSdk HIGH.

**Note:** on-disk `data/ledger.jsonl` is currently broken at seq 7 (left from a
prior tamper demo; gitignored local data, not caused by this pass). Re-seal with
the app's "Restore" / `POST /ledger/dev/rebuild` (VERIS_DEMO=1) before demoing.

## SIH26106 — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence

Building the SIH26106 feature set into Veris by REUSING the verdict engine,
ledger, enrichment and explanation UNCHANGED. Detection is commodity; we win on
chain-of-custody evidence + graph campaign attribution. `decide()`, the hash
chain, and `/ledger/verify` are never modified; the LLM explains/assists, never
overrides hard signals. Everything runs offline via bundled fixtures.

**Brief component → implementation (TABLE-STAKES — DONE, 132 tests, offline):**
| Brief KC | Built |
|---|---|
| Ingestion | `/check/email` (.eml + raw), stdlib `email` parser (no new dep) |
| Header/protocol | SPF/DKIM/DMARC (Authentication-Results), From↔Return-Path, Reply-To, Received-chain originating IP → cited signals |
| Fraud/NLP | deterministic urgency/credential/payment-diversion/fake-invoice signals + **ML** (`ml_phishing_likelihood`, one capped cited signal, sklearn LogReg, offline model) → 5-label (legitimate/suspicious/impersonated/phishing/fraud-related) |
| Origin & location | `app/geo.py`: geolocate (offline map + keyless ip-api, cached) + TOR/hosting/**origin-vs-claim** flags |
| Domain intel | `app/domain_intel.py`: WHOIS age/registrar + DNS/MX (offline map + python-whois/dnspython) |
| Links/attachments | body links + sender domain routed through the EXISTING `run_offline_checks` url engine |

**DIFFERENTIATORS — DONE:** (7) chain-of-custody forensic case file
(`/check/email?case=true`): grouped findings + chain-of-custody (signed head +
`/ledger/verify` status) + CERT-In/NCRP/1930 export, prosecution-ready. (8)
`networkx` graph campaign attribution (`/email/campaign`): shared-artifact
clustering (IP/ASN/X-Mailer/reply-drop/relay) -> "these 4 = 1 campaign" at 99%
with confidence-based attribution (spoofed-domain / anonymized-infra /
direct-actor); seed 4-email fixture set under `fixtures/email/campaign/`.
(10) **DONE** — privacy backend: PII masking (`?mask`/`VERIS_MASK_PII`, display
only; evidence/ledger keep real data), `GET /privacy/policy` (retention +
never-purge preservation rule), and evidence-preservation logging (case-file
exports appended to the ledger as `preservation` events).
(9) **DONE** — investigator console (`apps/mobile/src/app/email.tsx`): paste
`.eml` → forensic dashboard (colour-coded verdict + score, SPF/DKIM/DMARC
indicators, sender trace + geolocation, domain intel, cited evidence, proactive
high-risk banner), consumes `/check/email`. Home has a prominent entry point.
APK defaults to the live engine. **Follow-on:** mobile campaign-graph view needs
a small JSON variant of `/email/campaign` (currently multipart-only) + a redeploy.
143 backend tests. **SIH26106 feature set complete** (table-stakes + both
differentiators + privacy + console); engine deployed live.

**Why a hash-chain, not a blockchain (theme = "Blockchain & Cybersecurity").**
We needed tamper-evidence and chain-of-custody, not distributed consensus. A
signed SHA-256 hash-chain gives court-admissible integrity with instant offline
verification (`/ledger/verify` names the first altered record). A blockchain
would add consensus overhead and latency for zero benefit on a single-custodian
evidence log — so it is a deliberate non-goal (see ARCHITECTURE.md). One-liner
for judges: *"tamper-evidence and chain-of-custody, not distributed consensus."*

**Dependencies added (all verified maintained + permissive):** `python-whois`
(MIT), `dnspython` (ISC), `scikit-learn` (BSD-3) + `joblib`. Geo/reputation use
existing `httpx` (keyless ip-api; AbuseIPDB optional, backend-env only — not yet
wired). ML corpus is a compact curated seed (`fixtures/ml/email_corpus.jsonl`),
swappable for the full set. The MODEL is trained on a larger public phishing
corpus (`fixtures/ml/email_corpus_full.csv` — a balanced 6,000-row sample,
3,000 phishing / 3,000 legit, subsampled by `scripts/prep_corpus.py` from the
public zefang-liu/Kaggle phishing-email set). **Honest metrics (held-out 80/20
split, test=1,200): accuracy 0.973, phishing precision 0.964 / recall 0.983 /
F1 0.974, legit precision 0.983 / recall 0.963.** Trained model committed at
`app/models/email_clf.joblib`; retrain via `scripts/train_email_classifier.py`.
The model remains ONE capped cited signal, not the decider.

**Note:** on-disk `data/ledger.jsonl` still shows `/ledger/verify` false — a
PRE-EXISTING break at seq 7 from an earlier tamper demo, unrelated to email work;
re-seal with `POST /ledger/dev/rebuild` (VERIS_DEMO=1) before demoing.

## Demo-prep checklist (run before EVERY demo — don't skip under pressure)

1. Start the engine with the demo flags: `VERIS_DEMO=1` (enables the
   tamper/rebuild controls) and `VERIS_OFFLINE=1` for the offline demo path.
2. **Re-seal the ledger green:** `POST /ledger/dev/rebuild` → `GET /ledger/verify`
   must return `{"ok": true}`. (The on-disk `data/ledger.jsonl` can carry an old
   break from a previous demo — this clears it.)
3. Sanity-check the email demo, offline: `POST /check/email` with
   `fixtures/email/phishing_kyc.eml` → `likely_scam` / `impersonated`;
   `bec_invoice.eml` → `fraud-related`; `legit_statement.eml` → `safe`.
4. **Tamper demo is re-triggerable on demand** (verified): `POST /ledger/dev/tamper`
   → `/ledger/verify` shows `ok:false` + the broken record (RED) → `POST
   /ledger/dev/rebuild` → `ok:true` (GREEN). Repeat as many times as needed.
5. Engine URL in the app: set to the hosted **HTTPS** URL (cleartext is blocked).

## Known cleanups / to-do
- ~~**RECORD_AUDIO** permission~~ — DONE (stripped; not in the built manifest).
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
