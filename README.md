# Veris

Verifiable digital-fraud detection and tamper-evident cyber-incident reporting.
Built for Smart India Hackathon 2026.

Veris answers one question that most scam detectors dodge: **how do you know?**
Every verdict is produced by deterministic checks against named data sources,
and every signal is returned with its citation. A language model is used only
to explain that evidence in plain English and a regional language -- it never
decides, and never changes, the verdict.

## Status

| Phase | What | State |
|---|---|---|
| 0 | Monorepo, shared schema, health route | done |
| 1 | Verdict engine: deterministic checks | done |
| 2 | Explanation layer (Groq, explains only) | done |
| 3 | Tamper-evident evidence ledger | done |
| 4 | Android app (share-sheet intake, evidence panel) | done |
| 5 | Point-of-attack: APK static analysis | done (1 of 3, others declined) |
| 6 | India grounding + adversarial demo | done |
| 7 | Demo hardening | done |

## Run the whole demo, offline

One command, no network, no keys, throwaway ledger. If this exits 0 on a cold
machine, the demo works:

```bash
python scripts/demo_all.py
```

It runs every claim the pitch makes: the homoglyph catch, the cited evidence,
the Marathi explanation, the fake-loan APK, tamper detection, and the
complaint packet.

| Demo | What it shows |
|---|---|
| `scripts/demo_all.py` | everything, offline, with pass/fail checks |
| `scripts/demo_adversarial.py` | naive detector 5/9 vs Veris 9/9 |
| `scripts/demo_ledger.py` | forge the log, watch the chain catch it |
| `scripts/demo_apk.py` | fake loan app judged on its manifest |

- **[90-second demo script](docs/DEMO_SCRIPT.md)** — what to say, in order, with answers to the hard questions
- **[Architecture](docs/ARCHITECTURE.md)** — the flow, the trust boundaries, and the deliberate non-goals

## Definition of done

| Requirement | Status | Evidence |
|---|---|---|
| Verdict is deterministic; every signal cited; LLM only explains | done | `app/rules.py` is the only writer of a verdict; `Explanation` has no verdict field |
| Tamper-evident ledger + NCRP packet + live tamper detection | done | `scripts/demo_ledger.py` |
| Android app, share-sheet intake, evidence panel, works offline | done | verified on device with a real `ACTION_SEND` intent |
| At least one point-of-attack feature | done | APK static analysis; 3 others declined in writing |
| Adversarial demo that beats a naive detector | done | 9/9 vs 5/9 |
| Runs from README on a clean machine | done | fresh venv, no keys: 91 tests + 4/4 demos pass |
| Ponytail audit clean | done | pyflakes clean over 2,109 lines |
| No restricted permissions in the Play build | done | release manifest: `INTERNET` + `ACCESS_NETWORK_STATE` only |
| No definitive accusations; never auto-contacts an officer | done | output says "likely … verify"; every portal link is user-tapped |
| **Recorded fallback demo video** | **not done — yours to record** | see [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md#fallback-video) |

The last row cannot be automated. Record `python scripts/demo_all.py` plus the
phone flow before demo day and keep it on the presenting machine.

## Layout

```
services/verdict-engine/   Python FastAPI -- the deterministic brain
packages/shared/           verdict schema, mirrored for Python and TypeScript
fixtures/                  seed scams + safe samples, so the demo runs offline
apps/mobile/               Expo React Native app (Phase 4)
tooling/                   ponytail checkout (agent discipline, not a dependency)
```

## Run the verdict engine

Requires Python 3.11+ (tested on 3.13).

```bash
cd services/verdict-engine && python -m venv .venv
```

Then install and start. On Windows (Git Bash / PowerShell):

```bash
services/verdict-engine/.venv/Scripts/python -m pip install -r services/verdict-engine/requirements.txt
```

```bash
cd services/verdict-engine && .venv/Scripts/python -m uvicorn app.main:app --reload --port 8000
```

On macOS or Linux use `.venv/bin/python` in place of `.venv/Scripts/python`.

Check it:

```bash
curl http://127.0.0.1:8000/health
```

```json
{ "status": "ok", "engine_version": "0.1.0" }
```

Interactive API docs are at http://127.0.0.1:8000/docs.

## Check something

`POST /check` takes raw text -- a whole SMS, a bare domain, a UPI id, a phone
number, an APK hash -- works out what it is, and returns the evidence.

```bash
curl -X POST http://127.0.0.1:8000/check -H "Content-Type: application/json" -d '{"input":"https://xn--icicibnk-66g.com/login"}'
```

That input is a Cyrillic-`а` lookalike of `icicibank.com`. A substring check
sees nothing wrong with it. Veris returns:

```json
{
  "verdict": "likely_scam",
  "score": 65,
  "signals": [
    {
      "id": "homoglyph_impersonation",
      "source": "Unicode UTS #39 confusables skeleton",
      "value": "'icicibаnk.com' renders as 'icicibank.com' (ICICI Bank) using lookalike characters",
      "observed_at": "2026-08-18T...+00:00",
      "weight": 65
    }
  ],
  "rules_fired": ["homoglyph_impersonation (+65): ...", "score 65 -> likely_scam (likely_scam >= 60, suspicious >= 30)"]
}
```

Note what is *not* in that response: an opinion. The verdict is the arithmetic
of the signal weights, and every signal names the source it came from.

### What it checks, offline

| Check | Source | Weight |
|---|---|---|
| Blocklist hit | PhishTank / URLhaus / OpenPhish local snapshots | 70 |
| Homoglyph impersonation | Unicode UTS #39 confusable skeleton | 65 |
| Brand as subdomain | Public Suffix List registrable-domain comparison | 55 |
| Typosquat | Levenshtein <= 2 vs curated Indian brand list | 45 |
| Reported UPI VPA | local reported list | 70 |
| Malformed UPI VPA | NPCI VPA format rules | 30 |
| Userinfo deception (`brand.com@evil.top`) | RFC 3986 URL parsing | 60 |
| Raw IP as host | host is a literal IP address | 45 |
| Credit offer from an unregulated domain | RBI-regulated lender seed list | 35 |
| Verified brand domain | curated Indian brand list | allowlist |

Scores are summed and capped at 100: `>= 60` is `likely_scam`, `>= 30` is
`suspicious`, below that `safe`.

### The explanation layer

`POST /check` also returns an `explanation` in English and a regional language
(`"language": "mr"` for Marathi, `"hi"` for Hindi). It is written by a
Groq-hosted model that is handed **only** the structured evidence.

The model is fenced in three ways, because an unfenced LLM in a fraud tool is
a liability:

1. **Structural.** The `Explanation` type has no verdict field. Any `verdict`
   key the model returns is dropped.
2. **Contradiction guard.** Prose arguing against the verdict it is meant to
   explain is discarded and re-prompted.
3. **Invented-source guard.** If the text name-drops VirusTotal or RDAP when
   no such signal was gathered, it is discarded.

After two failed attempts -- or with no API key, no network, or
`VERIS_OFFLINE=1` -- it falls back to a deterministic template built from the
same signals. The fallback is not a degraded mode; it is the offline demo
path, and it produces real Marathi and Hindi:

> ही बहुधा फसवणूक आहे. कोणतीही वैयक्तिक माहिती किंवा OTP देऊ नका...
> या पत्त्यात खऱ्या बँकेच्या नावासारखी दिसणारी बनावट अक्षरे वापरली आहेत.

Set `GROQ_MODEL` if your account has different models available. Groq retired
`llama-3.3-70b-versatile` on 2026-08-16; the default is now
`openai/gpt-oss-120b`.

### What it adds when online

Safe Browsing v4, VirusTotal v3 (cached 24h for the ~4 req/min free tier),
RDAP registration date, and the live TLS certificate. All four are
**enrichment**: if a key is missing or the network is down they contribute
nothing and the verdict still returns. `VERIS_OFFLINE=1` disables them
outright.

## Run the tests

```bash
cd services/verdict-engine && .venv/Scripts/python -m pytest -q
```

## Configuration

Copy `.env.example` to `.env` and fill in what you have. **Every key is
optional.** With no keys at all the engine still returns a verdict from local
blocklists and offline checks -- that is deliberate, so a live demo never
depends on a network call. Set `VERIS_OFFLINE=1` to block outbound calls
entirely.

## The Android app

`apps/mobile` is an Expo (SDK 57) React Native app in TypeScript. Four
screens: Home (paste or share-sheet intake), Result (verdict badge, evidence
panel, explanation with a language toggle), Report (complaint packet), and
Ledger (chain status and history).

### It needs a development build, not Expo Go

Veris registers itself as an Android **share target**, which requires an
`intent-filter` in the manifest. Expo Go can only run standard SDK modules and
cannot load custom native config, so share-sheet intake — and the Phase 5
call-screening module — will not work there. You need a dev build.

The intent filter is declared by the `expo-share-intent` **config plugin** in
`app.json`, never by hand-editing `android/`, which `prebuild` regenerates.

### One-time setup

Requires Android Studio (for the SDK and its bundled JDK), a device with
USB debugging on, and the verdict engine running.

```bash
adb reverse tcp:8000 tcp:8000
```

That maps the phone's `localhost:8000` to the engine on your machine. If the
port is taken, run the engine elsewhere and point the app at it with
`apps/mobile/.env`:

```bash
EXPO_PUBLIC_VERIS_API=http://127.0.0.1:8010
```

Then build and install to the connected device:

```bash
cd apps/mobile && npx expo run:android
```

If `java -version` shows anything below 17, point `JAVA_HOME` at the JDK
bundled with Android Studio (`C:\Program Files\Android\Android Studio\jbr` on
Windows) rather than installing another one.

### Day-to-day iteration

```bash
cd apps/mobile && npx expo start --dev-client
```

JS and UI changes hot-reload over USB. Only re-run `expo run:android` when
**native** config changes — adding an intent filter, or the Phase 5 call
screening module.

### Troubleshooting

**"Engine did not respond" in the app.** `adb reverse` does not survive an adb
server restart (or unplugging the phone). Re-run it and check:

```bash
adb reverse tcp:8000 tcp:8000 && adb reverse --list
```

**Gradle fails with `InstallFailedException: ndk;27.1.12297006`.** React
Native 0.86 pins that exact NDK. Gradle auto-downloads it, but if the download
is interrupted it leaves a ~1 KB stub directory that looks installed and is
not. Delete `$ANDROID_HOME/ndk/27.1.12297006` and build again, or install the
NDK from Android Studio's SDK Manager (SDK Tools -> NDK, "Show Package
Details" -> 27.1.12297006).

**Gradle fails with `Cannot snapshot ... libc++_shared.so: not a regular file`.**
The real cause is not your project folder: it is the **NDK's own copy** of
`libc++_shared.so` being a cloud placeholder (a reparse point). CMake copies
that file into every native module's build directory, and each copy inherits
the placeholder state -- which is why the failure appears to hop from module to
module, and why moving the repo does not fix it.

Find and hydrate any placeholder inside the NDK:

```powershell
Get-ChildItem "$env:LOCALAPPDATA/Android/Sdk/ndk" -Recurse -File | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }
```

Rewrite each one in place (read the bytes, delete, write them back), then
delete the contaminated copies so Gradle re-creates them:

```powershell
Get-ChildItem apps/mobile/node_modules -Recurse -Directory -Filter cxx | Remove-Item -Recurse -Force
```

Keeping the repo outside a synced folder is still worth doing -- OneDrive also
causes `rm` to fail with "device or resource busy" -- but on its own it does
not fix this.

**`java -version` shows 1.8.** Gradle needs JDK 17+. Point `JAVA_HOME` at the
JDK bundled with Android Studio instead of installing another:
`C:\Program Files\Android\Android Studio\jbr`.

### Permissions

The **release** build requests `INTERNET` and nothing else. There is no
`READ_SMS` or `READ_CALL_LOG` -- both are banned by Play policy and neither is
needed.

`expo-share-intent` requests `SYSTEM_ALERT_WINDOW`, `VIBRATE`, and external
storage by default for file sharing we do not use. Those are stripped via
`android.blockedPermissions` in `app.json`; verified absent on-device with
`adb shell dumpsys package in.veris.app`.

**Verified** on the release manifest, not just asserted:

```bash
cd apps/mobile/android && ./gradlew :app:processReleaseMainManifest
```

```
android.permission.INTERNET
android.permission.ACCESS_NETWORK_STATE
in.veris.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION   (internal, RN-generated)
```

A **debug** build additionally carries `SYSTEM_ALERT_WINDOW`, from React
Native's own `ReactAndroid/src/debug/AndroidManifest.xml` (the dev overlay).
Gradle merges that manifest only for debug variants, which the release output
above confirms.

**Native config changes need a clean prebuild.** `expo run:android` skips
prebuild when `android/` already exists, so edits to `app.json` silently do
nothing until you run:

```bash
npx expo prebuild --clean -p android
```

## APK static analysis

```bash
python scripts/demo_apk.py
```

Reads the permissions declared in an APK's manifest **without installing or
running the app** -- which is precisely what a victim cannot do before tapping
Install.

```
  a fake instant-loan app
  package : com.instant.rupee.loan  v3.1.4
  verdict : LIKELY_SCAM  (score 100/100)
     +35  READ_CONTACTS -- can copy your whole contact list
     +35  READ_SMS -- can read your SMS, including bank OTPs
     +45  requests contacts AND SMS together -- the combination used to
          harvest a contact list and intercept bank OTPs
```

The fixture is a **real APK**, built with `aapt2` from the Android SDK, not a
mocked JSON blob. The pairing is the point: harvest the contact list,
intercept the bank OTP, then threaten to message everyone the victim knows.
That is the Indian fake-loan-app playbook, and it is visible in the manifest
before the app ever runs.

Veris analyses **itself** in the same demo and does not score zero -- its debug
build carries `SYSTEM_ALERT_WINDOW` from React Native's dev overlay. A tool
that exempted itself from its own rules would not be worth trusting.

Upload one to the engine:

```bash
curl -F "file=@fixtures/apk/fake_loan_app.apk" http://127.0.0.1:8000/check/apk
```

MobSF is wired in as **optional enrichment** (`MOBSF_URL` + `MOBSF_API_KEY`)
and is never required. A 2 GB container must not stand between a victim and a
verdict, so the offline permission analysis produces the verdict on its own.

### Point-of-attack features NOT built, and why

Stated plainly rather than left as half-working stubs:

| Feature | Status |
|---|---|
| **Call screening** (`CallScreeningService` + `RoleManager`) | **not built.** Needs a native Kotlin module and the user to hand Veris the system call-screening role. Achievable, but it is a second native surface for one demo moment. |
| **On-device model** (Gemma via MediaPipe / LiteRT) | **not built.** The deterministic checks already run offline, so an on-device model would add a ~1 GB download to explain evidence the template layer already explains in Marathi and Hindi. |
| **Accessibility-service overlay warning** | **not built, and not recommended.** Play policy treats accessibility-service use for non-accessibility purposes as a violation. Sideload-only at best. |
| **SMS screening** | **deliberately impossible.** `READ_SMS` / `READ_CALL_LOG` are banned by Play policy. The compliant route is the SMS Retriever / User Consent API, and share-sheet intake already covers the demo. |

## The adversarial demo

```bash
python scripts/demo_adversarial.py
```

Runs the same nine URLs past a naive detector -- "does the URL contain a known
bank domain?", which is genuinely what a weekend project ships -- and past
Veris:

```
  naive detector : 5/9 correct
  Veris          : 9/9 correct
```

The naive rule fails in both directions. It waves through every impersonation
that merely contains the brand string:

| Attack | Naive | Veris |
|---|---|---|
| `hdfcbank.com.secure-verify.top` | safe | likely_scam -- served by `secure-verify.top` (Public Suffix List) |
| `hdfcbank.com@secure-verify.top` | safe | likely_scam -- text before `@` is a username, not a host |
| `sbi.co.in.login-verify.icu` | safe | likely_scam -- brand as a subdomain label |
| `xn--icicibnk-66g.com` | scam | likely_scam -- Cyrillic skeleton match (UTS #39) |

...and it calls a **real** bank a scam for not being on its list
(`bankofmaharashtra.in`). Veris reports that nothing flagged it -- absence of
evidence stated as absence of evidence, not as safety.

## India grounding

| Source | How it is used | Status |
|---|---|---|
| Indian bank / UPI / govt brand domains | allowlist + homoglyph and typosquat targets | integrated (`fixtures/brands_in.json`) |
| RBI-regulated lenders | flags instant-credit offers from domains tied to no regulated lender | **seed list**, integrated (`fixtures/rbi_regulated_lenders.json`) |
| NCRP / cybercrime.gov.in | complaint packet fields + deep link | align + deep-link, **no public API** |
| 1930 helpline | `tel:` deep link, packet written to be read aloud | align, **no API** |
| Sanchar Saathi / Chakshu | deep link from the Report screen | **no public API** |
| Suspect Registry / DoT FRI | named as a future MoU integration only | **bank-only backend, not integrated** |

Two honesty rules hold here. The RBI list is a hand-compiled **seed**, not a
copy of RBI's directory, so a domain missing from it scores *suspicious* with
the words "not on our list -- verify on the RBI directory", never "illegitimate".
And Veris opens these portals for the user; it never files anything and never
contacts an officer.

## Protection features (on the phone)

### Automatic warnings (the notification guard)

The feature most people actually want: a message arrives, and a second later
the notification bar says whether it is a scam. No pasting, no sharing.

Veris registers a `NotificationListenerService`, so Android hands it every
notification other apps post -- SMS, WhatsApp, Gmail, anything. It scores the
text with the same deterministic checks the engine uses, and if it looks like
a scam it posts **its own** warning next to the message. Tapping that warning
opens Veris with the text for the full evidence panel.

Three guarantees, and they are in the code, not just the pitch:

1. **It never blocks anything.** No notification is dismissed, altered, or
   hidden. Veris only adds a warning of its own. Your messages stay yours.
2. **Nothing leaves the phone.** The text is scored on-device against a rules
   file bundled into the APK and then discarded. It is never sent to our
   server, never written to the ledger, never stored.
3. **It needs no restricted permission.** No `READ_SMS`, no `READ_CALL_LOG`.

Notification access is granted on a dedicated system settings screen that
warns the user Veris can read all notifications. That warning is accurate and
the app says so plainly rather than talking the user past it -- see the
Protection screen.

Rules live in `fixtures/ondevice_rules.json` (brands, scam wording, reported
UPI ids and numbers, blocked hosts, weights, thresholds) and are bundled by
`plugins/withNotificationGuard.js`. Editing that one file changes what both
the guard and the call screener catch.

**What it cannot see.** The guard reads what is *in the notification*. If the
user has message previews turned off, or the messaging app truncates a long
message, Veris only sees what was shown. It also cannot see a message that
arrives while notifications for that app are silenced. The share sheet still
handles those in full -- this is an early-warning layer, not a replacement for
checking something properly.

Try it after installing: send yourself an SMS reading
`Your SBI KYC has expired, account blocked within 2 hours. Pay kycupdate2026@ybl`.

### Call screening

Veris can register as Android's call screener. When a number that is not in
your contacts rings, Android hands it to `VerisCallScreeningService`, which has
a few seconds to answer. It checks the number against a scam list **bundled
into the APK**, so it works with no network and no server, and rejects a match
before the phone rings.

- Needs the `CALL_SCREENING` role, which the user grants explicitly.
- Needs **no** `READ_CALL_LOG`: screening only ever sees the number currently
  calling, never your history.
- Declared by `plugins/withCallScreening.js`, a config plugin, so it survives
  `prebuild`. The Kotlin service and the bundled number list are generated,
  never hand-edited into `android/`.
- An unrecognised number is always allowed through. A fraud tool that silently
  swallows calls is worse than one that does nothing.

Enable it on the Protection screen. Some OEM builds reserve the role for their
own dialler, so the app also offers a link to Default apps settings.

### On-device triage

If the engine is unreachable, the app still answers, using the same rule as the
backend: deterministic checks over local data, each citing what it matched.

It runs scam-wording patterns (in the languages the messages actually arrive
in), a bundled reported-VPA list, and URL structure checks -- userinfo
deception, brand-as-subdomain, non-English characters in a hostname, raw IP
hosts.

It is deliberately weaker than the server: no blocklist feeds, no Unicode
confusables table, no RDAP. Wording alone can never reach `likely_scam`, every
result is stamped `engine_version: "on-device"`, and the Result screen says so
in a banner. Run it:

```bash
cd apps/mobile && node --experimental-strip-types scripts/check-ondevice.mjs
```

### Reading SMS automatically

Veris does not, on purpose. Google Play only allows `READ_SMS` for an app that
is the device's **default SMS handler** -- so it is possible, but it would mean
replacing the user's messaging app and gaining standing access to every message
they receive, in exchange for checking a link.

The share sheet gets the same result with one tap and no permission. The full
analysis, including the two OTP-only APIs that look compliant but detect
nothing, is in [docs/SMS_ACCESS.md](docs/SMS_ACCESS.md).

## The evidence ledger

Every check is appended to `data/ledger.jsonl` as one line carrying the
SHA-256 hash of the line before it. Edit any byte of any earlier record and
every hash after it stops matching.

See it catch a forgery:

```bash
python scripts/demo_ledger.py
```

It records three incidents, exports a complaint packet, edits a verdict in the
log, and shows the chain naming the broken record:

```
broken at : record #2
reason    : contents were altered: stored hash c3eaa2f665a3a232...
            but the data now hashes to 29f98762e4c63b21...
```

Recompute the tampered record's own hash to cover your tracks and the break
just moves downstream, because record #3 still points at the original:

```
broken at : record #3
reason    : prev_hash does not match the previous record's hash
```

To hide an edit you must rewrite every record after it — and then the signed
chain head no longer matches.

| Endpoint | What |
|---|---|
| `GET /ledger/events` | every recorded event, oldest first |
| `GET /ledger/verify` | walk the chain, report the first break and why |
| `POST /ledger/report` | record complaint details, return an NCRP-aligned packet |

### Why a hash chain and not a blockchain

A blockchain solves distributed consensus among mutually distrusting parties.
That is not this problem. This problem is detecting after-the-fact edits to
one evidence log, which a hash chain solves completely — with no network, no
miners, and no tokens, which is also why it still works on a phone in a
village with no signal.

What a chain alone does not give you is proof of *when*. The chain head is
signed (HMAC-SHA256, `VERIS_LEDGER_KEY`) so a full rewrite needs the key, and
`timestamp_anchoring` in the packet states plainly that wall-clock time is
asserted by the device rather than by a trusted third party. RFC 3161
anchoring is the upgrade path and is **not** implemented — the packet says so
rather than implying a timestamp we do not have.

### The complaint packet

`POST /ledger/report` returns the fields NCRP's financial-fraud flow asks for
(incident time, amount, payment mode, suspect UPI/account/bank, UTR, suspect
URLs and phone, screenshot hashes) alongside the automated findings, the chain
verification status, the data-source attributions, and where to file.

Veris **submits nothing anywhere**. There is no public NCRP API, and filing on
someone's behalf would be wrong even if there were. The packet goes to the
user; the user decides.

If the chain is broken, the packet says so — `chain_verified: false` with the
offending sequence number. A packet that quietly omitted tampering would be
evidence laundering.

## Attribution

URL reputation enrichment uses Google Safe Browsing ("Advisory provided by
Google") and VirusTotal. Blocklist data comes from PhishTank, URLhaus
(abuse.ch), and OpenPhish.

## Notes for contributors

Read [CLAUDE.md](CLAUDE.md) first -- it holds the one rule that shapes the
whole design, plus the legal and Play-policy constraints.
