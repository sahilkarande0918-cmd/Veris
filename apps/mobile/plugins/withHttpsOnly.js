/**
 * Expo config plugin: network + manifest hardening.
 *
 * TLS-only networking (strict, hosted-only). Veris talks to its verdict engine
 * and nothing else over the network. This plugin makes that connection
 * HTTPS-only at the OS level:
 *
 *   - usesCleartextTraffic="false" on the application, and
 *   - a network security config whose base-config forbids cleartext to EVERY
 *     host, with no per-domain exceptions.
 *
 * Consequence (accepted by design): the old "paste http://<laptop-ip>:8010"
 * same-Wi-Fi demo path no longer connects. The engine must be reached over
 * HTTPS (a hosted URL). If the engine is unreachable, the app already falls
 * back to on-device triage, so nothing crashes.
 *
 * Task-hijacking / StrandHogg mitigation. Expo's MainActivity uses
 * launchMode="singleTask", which MobSF flags as vulnerable to StrandHogg 1/2.
 * Setting an empty taskAffinity on the application stops a malicious app from
 * planting an activity on our task's back stack.
 *
 * Certificate pinning (Tier 2 #9), OFF by default. When app.json sets
 * extra.enginePinHost + extra.enginePins, the generated network security config
 * pins that host to the given SHA-256 public-key hashes. Empty => no pinning, so
 * a wrong pin can never brick the demo unless someone deliberately turns it on.
 * See docs/CERT_PINNING.md.
 *
 * Done as a config plugin so it survives `expo prebuild`, matching the other
 * plugins in this folder.
 */

const { withAndroidManifest, withDangerousMod, AndroidConfig } = require("expo/config-plugins")
const fs = require("fs")
const path = require("path")

// Certificate pinning is OFF by default (empty pin => no pinning), because a
// wrong pin bricks every connection. Enable it by setting, in app.json:
//   "extra": { "enginePinHost": "your-engine.example.com",
//              "enginePins": ["base64sha256==", "backupbase64sha256=="] }
// then `npx expo prebuild --clean -p android`, rebuild, and TEST ON DEVICE.
// See docs/CERT_PINNING.md for how to compute the pins.
function buildNetworkSecurityConfig(host, pins) {
  const pinBlock =
    host && Array.isArray(pins) && pins.length
      ? `
    <domain-config>
        <domain includeSubdomains="true">${host}</domain>
        <pin-set>
${pins.map((p) => `            <pin digest="SHA-256">${p}</pin>`).join("\n")}
        </pin-set>
    </domain-config>`
      : ""
  return `<?xml version="1.0" encoding="utf-8"?>
<!-- Veris: TLS only. Cleartext HTTP is refused to every host. -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>${pinBlock}
</network-security-config>
`
}

function withManifestAttrs(config) {
  return withAndroidManifest(config, (cfg) => {
    const app = AndroidConfig.Manifest.getMainApplicationOrThrow(cfg.modResults)
    app.$["android:usesCleartextTraffic"] = "false"
    app.$["android:networkSecurityConfig"] = "@xml/network_security_config"
    app.$["android:taskAffinity"] = ""
    // MobSF's StrandHogg check reads taskAffinity on the activity element, not
    // the inherited application value, so set it on MainActivity directly too.
    const activity = AndroidConfig.Manifest.getMainActivityOrThrow(cfg.modResults)
    activity.$["android:taskAffinity"] = ""
    return cfg
  })
}

function withNetworkSecurityConfigFile(config) {
  const host = config.extra && config.extra.enginePinHost
  const pins = config.extra && config.extra.enginePins
  const xml = buildNetworkSecurityConfig(host, pins)
  return withDangerousMod(config, [
    "android",
    (cfg) => {
      const dir = path.join(cfg.modRequest.platformProjectRoot, "app", "src", "main", "res", "xml")
      fs.mkdirSync(dir, { recursive: true })
      fs.writeFileSync(path.join(dir, "network_security_config.xml"), xml)
      return cfg
    },
  ])
}

module.exports = (config) => withNetworkSecurityConfigFile(withManifestAttrs(config))
