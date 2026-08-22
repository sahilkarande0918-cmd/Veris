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
 * Done as a config plugin so it survives `expo prebuild`, matching the other
 * plugins in this folder.
 */

const { withAndroidManifest, withDangerousMod, AndroidConfig } = require("expo/config-plugins")
const fs = require("fs")
const path = require("path")

const NETWORK_SECURITY_CONFIG = `<?xml version="1.0" encoding="utf-8"?>
<!-- Veris: TLS only. Cleartext HTTP is refused to every host. -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
`

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
  return withDangerousMod(config, [
    "android",
    (cfg) => {
      const dir = path.join(cfg.modRequest.platformProjectRoot, "app", "src", "main", "res", "xml")
      fs.mkdirSync(dir, { recursive: true })
      fs.writeFileSync(path.join(dir, "network_security_config.xml"), NETWORK_SECURITY_CONFIG)
      return cfg
    },
  ])
}

module.exports = (config) => withNetworkSecurityConfigFile(withManifestAttrs(config))
