# Installing Veris on an Android phone

The app is distributed as an APK you install directly. It is not on the Play
Store, so Android will ask you to confirm — that is normal for a hackathon
build and the steps below are the same ones any sideloaded app needs.

**Requirements:** Android 10 or newer, about 120 MB free.

## For teammates: install it

1. Open the download link (or scan the QR code) on the **phone**, not a laptop.
2. Tap the `.apk` file when it finishes downloading.
3. Android will say *"For your security, your phone is not allowed to install
   unknown apps from this source"*. Tap **Settings**, turn on **Allow from
   this source**, then press back and tap **Install**.
4. Open Veris.

If Play Protect warns that the app was not scanned, tap **Install anyway**.
That warning appears for every app not distributed through the Play Store.

## Turn on the two protections

Both need a deliberate tap from you. Android will not let an app grant these
to itself, and that is a good thing.

Open **Veris → Protection settings**:

- **Turn on automatic warnings** — allow notifications when asked, then find
  Veris in the list that opens and enable it. Now any scam SMS, WhatsApp
  message or email gets a warning in your notification bar within about a
  second.
- **Enable call screening** (optional) — lets Veris reject calls from reported
  scam numbers before your phone rings. Some phones reserve this for their own
  dialler; if yours does, the app will tell you and offer the settings screen.

Veris never blocks or changes your messages. It only adds its own warning.

## Try it

Send yourself a message containing:

```
Your SBI KYC has expired. Account blocked within 2 hours. Pay kycupdate2026@ybl
```

You should get a **Likely scam** warning. Tap it to see exactly which checks
fired and where each one came from.

To test by hand instead, open Veris and paste:

```
https://xn--icicibnk-66g.com/login
```

That is a fake `icicibank.com` built from Cyrillic lookalike letters. Veris
catches it; a plain "does this contain icicibank.com?" check does not.

## What works without the internet

Everything on the phone: the notification guard, call screening, and the
offline triage that runs when the server cannot be reached. The bundled rules
travel inside the APK.

Connecting the app to the verdict engine adds the heavier checks (live domain
registration lookups, certificate inspection, reputation feeds). Without it
you still get a verdict, clearly labelled as the lighter on-device one.

---

# For the maintainer: publishing a build

`gh` is not required. From the repo:

1. Build the APK:

```bash
cd apps/mobile/android && ./gradlew :app:assembleRelease -PreactNativeArchitectures=arm64-v8a,armeabi-v7a
```

   Output: `apps/mobile/android/app/build/outputs/apk/release/app-release.apk`

2. Go to **github.com/sahilkarande0918-cmd/Veris → Releases → Draft a new
   release**, tag it (e.g. `v0.1.0`), drag the APK into the attachments box,
   and publish.

3. The QR code in `docs/download-qr.png` points at
   `.../releases/latest`, so it keeps working for every future release without
   being regenerated. To point it somewhere else:

```bash
python scripts/make_qr.py https://your-link-here
```

## A caveat worth knowing before you ship an update

This build is signed with the **debug keystore**, which is Expo's default.
That is fine for sideloading and for the hackathon, but:

- it cannot be uploaded to the Play Store, and
- if you later switch to a real keystore, everyone must **uninstall** the old
  app first. Android refuses to update an app whose signature changed.

Generate a proper keystore before any real distribution:
<https://reactnative.dev/docs/signed-apk-android>.

## If someone's phone refuses to install

- **"App not installed"** — an older Veris with a different signature is
  already there. Uninstall it first.
- **Very old phone** — the APK targets arm64 and armeabi-v7a, which covers
  essentially every real device. A 32-bit-only x86 tablet would need a rebuild
  with `-PreactNativeArchitectures=x86`.
