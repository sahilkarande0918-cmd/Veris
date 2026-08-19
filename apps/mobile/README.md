# Veris — Android app

Expo (SDK 57) + expo-router, TypeScript. Share-sheet intake, evidence panel,
complaint packet, ledger history.

Setup, dev-build rationale, and troubleshooting live in the root
[README](../../README.md#the-android-app). Short version:

```bash
adb reverse tcp:8000 tcp:8000 && npx expo run:android
```

Then iterate with `npx expo start --dev-client`. Re-run `expo run:android`
only when native config changes, and always `npx expo prebuild --clean -p android`
after editing `app.json`.
