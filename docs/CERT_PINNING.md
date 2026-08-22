# Certificate pinning (app → backend)

Pinning ties the app to your engine's exact TLS public key, so a mis-issued or
attacker-supplied certificate is rejected even if it chains to a trusted CA.

**It is OFF by default on purpose.** A wrong or expired pin makes the app refuse
*every* connection to the engine — which would break the demo. Turn it on only
after you can test on the physical demo device.

## 1. Compute the pins for your engine

Point this at your hosted HTTPS engine (e.g. `veris-xxxx.onrender.com:443`):

```bash
openssl s_client -connect veris-xxxx.onrender.com:443 -servername veris-xxxx.onrender.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

That base64 string is one pin. **Provide at least two** — the current leaf key
and a backup (your CA's intermediate key, or a spare key) — so a routine cert
rotation doesn't lock users out. Compute the intermediate's pin the same way
from the cert one step up the chain.

## 2. Enable it

In `apps/mobile/app.json`, add an `extra` block:

```json
"extra": {
  "enginePinHost": "veris-xxxx.onrender.com",
  "enginePins": ["PRIMARY_BASE64==", "BACKUP_BASE64=="]
}
```

## 3. Rebuild and test on the device

```bash
cd apps/mobile
npx expo prebuild --clean -p android      # regenerates network_security_config with the pin-set
# build the release APK, install on the demo device, and confirm a real /check works
```

If the app can no longer reach the engine after enabling, the pin is wrong or the
cert rotated — remove the `extra` block (or fix the pins) and rebuild. Leave it
**off** for the demo unless you have verified it end-to-end on the device.
