# Veris — MobSF Static Analysis Report

**Tool:** MobSF (Mobile Security Framework) **v4.5.2**, static analysis
**Artifact scanned:** `app-release.apk` (release build, R8/ProGuard enabled, arm64-v8a)
**Package:** `in.veris.app`  **APK MD5:** `eb21a2ab6cbf5d8f348bf9c432c8173b` (final Tier 1+2 build)
**Date:** 2026-08-22
**Raw report:** [`SECURITY_MobSF_report.json`](SECURITY_MobSF_report.json) (full MobSF output, 3.8 MB)

## Result

| Metric | Value |
|---|---|
| **MobSF security score** | **49 / 100** |
| High findings | 3 (all manifest heuristics — see below) |
| Warning findings | 5 |
| Secure findings | 2 (cleartext-disallowed, network security config present) |
| Trackers detected | **0** |
| Secrets / hardcoded keys | **0** |

The score is dominated by three heuristic manifest findings (minSdk level and the
`singleTask` launch mode). **Every Tier-1-class category MobSF checks for —
exposed secrets, weak network config, dangerous permissions, insecure storage —
is clean or fixed.** MobSF independently confirms the network hardening
("Base config is configured to disallow clear text traffic to all domains").

## Findings and disposition

### Fixed (Tier-1-class)

| # | MobSF finding | Severity | Fix applied |
|---|---|---|---|
| A | Clear-text traffic could be allowed | (network) | `usesCleartextTraffic="false"` + `network_security_config.xml` with `cleartextTrafficPermitted=false` for **all** hosts. MobSF now reports this as **secure**. |
| B | App data extractable via `adb backup` | Medium-class | `android:allowBackup="false"`. |
| C | Hardcoded secrets / API keys | High-class | None present — verified by MobSF (0 secrets) and by grepping the release bundle. All third-party keys (Groq/VirusTotal/Safe Browsing) live only server-side; the app calls the backend, the backend calls the APIs. |
| D | Dangerous permissions | High-class | Least-privilege: only `CAMERA` (QR scan) and `POST_NOTIFICATIONS` (scam warnings) are dangerous-class, both used and justified. No `READ_SMS` / `RECEIVE_SMS` / `READ_CALL_LOG` / `READ_CONTACTS` / `RECORD_AUDIO`. |
| E | Task hijacking vector (reparenting) | High | `android:taskAffinity=""` set on the application **and** on `MainActivity` — closes the task-reparenting vector. |

### Accepted with rationale (not Tier-1-class; would break a feature or device support)

| # | MobSF finding | Severity | Why accepted |
|---|---|---|---|
| F | `MainActivity` uses `launchMode="singleTask"` → StrandHogg 1.0 / 2.0 | High ×2 | `singleTask` is Expo's default and is **required** by the share-sheet intake (`expo-share-intent`) so one app instance handles incoming SEND intents. Removing it would break a verified core feature. The app-side mitigation (`taskAffinity=""`, finding E) is applied; StrandHogg 2.0 is additionally mitigated at the OS level on Android 9+ (API 28+). MobSF's rule keys statically on the `singleTask` attribute and cannot credit the runtime mitigation. **Recommend: accept.** |
| G | `minSdk=24` → installable on Android 7.0 | High | Expo SDK 57 default. Raising `minSdkVersion` to 26/28 clears this (and hardens StrandHogg 2.0) but drops pre-Android-8/9 devices. This is a product/compat decision. **Recommend: raise to 26 unless a demo device needs Android 7.** |
| H | `VerisCallScreeningService` is exported, protected by `BIND_SCREENING_SERVICE` | Warning | Required by the platform — a `CallScreeningService` **must** be exported for the OS to bind it, and is guarded by the system-signature permission. Not exploitable. |
| I | Base config trusts system CAs | Warning | Correct for talking to a hosted HTTPS engine over public CAs. Stricter pinning is **Tier 2, item #9** (certificate pinning) and is deferred to that phase. |
| J | `expo.modules.webbrowser.BrowserProxyActivity` sets taskAffinity; `androidx ProfileInstallReceiver` exported+`DUMP`-protected | Warning | Third-party (Expo web-browser, AndroidX profile-installer). Signature/`DUMP`-protected, not app-controlled, benign. |

## How to reproduce

```bash
# 1. MobSF (pip distribution) — needs JDK 17+ on PATH for jadx/apktool
python -m venv mobsf-venv && ./mobsf-venv/Scripts/pip install mobsf
JAVA_HOME="<Android Studio>/jbr" ./mobsf-venv/Scripts/mobsf   # note the printed REST API key
# 2. Scan the release APK via REST
#    POST /api/v1/upload  (file)            -> {hash}
#    POST /api/v1/scan    (hash)            -> full JSON report
# 3. The saved JSON is SECURITY_MobSF_report.json
```

_The verdict engine is never involved in the app's security posture: it runs on
the backend, and its verdicts are produced by deterministic checks, not the LLM.
This report concerns only the Android client artifact._
