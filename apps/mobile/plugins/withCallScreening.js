/**
 * Expo config plugin: Android call screening.
 *
 * Registers a CallScreeningService so Veris can be offered as the phone's
 * call screener. When a number that is not in the user's contacts rings,
 * Android hands it to us and we have a few seconds to answer "allow" or
 * "reject". We check it against a scam list bundled into the APK, so it
 * works with no network and no server -- which is the whole point of doing
 * this on the device rather than in the cloud.
 *
 * All of this is generated at prebuild time. Nothing here is hand-edited into
 * android/, because prebuild regenerates that directory.
 *
 * Play policy note: CallScreeningService needs the CALL_SCREENING role, which
 * the user grants explicitly. It does NOT need READ_CALL_LOG or READ_SMS.
 */

const { withAndroidManifest, withDangerousMod, AndroidConfig } = require("expo/config-plugins")
const fs = require("fs")
const path = require("path")

const SERVICE_CLASS = ".VerisCallScreeningService"

/** Bundle the scam-number list into the APK as an asset. */
function withScamNumberAsset(config) {
  return withDangerousMod(config, [
    "android",
    (cfg) => {
      const repoRoot = path.resolve(cfg.modRequest.projectRoot, "..", "..")
      const source = path.join(repoRoot, "fixtures", "scam_numbers.txt")
      const assetsDir = path.join(
        cfg.modRequest.platformProjectRoot,
        "app",
        "src",
        "main",
        "assets",
      )
      fs.mkdirSync(assetsDir, { recursive: true })

      let numbers = ""
      if (fs.existsSync(source)) {
        numbers = fs.readFileSync(source, "utf8")
      } else {
        console.warn("[veris-call-screening] fixtures/scam_numbers.txt not found; shipping an empty list")
      }
      fs.writeFileSync(path.join(assetsDir, "veris_scam_numbers.txt"), numbers, "utf8")
      console.log("[veris-call-screening] bundled scam number list into assets")
      return cfg
    },
  ])
}

/** Write the Kotlin service into the generated Android project. */
function withCallScreeningSource(config) {
  return withDangerousMod(config, [
    "android",
    (cfg) => {
      const pkg = cfg.android?.package
      if (!pkg) throw new Error("[veris-call-screening] android.package must be set in app.json")

      const dir = path.join(
        cfg.modRequest.platformProjectRoot,
        "app",
        "src",
        "main",
        "java",
        ...pkg.split("."),
      )
      fs.mkdirSync(dir, { recursive: true })
      fs.writeFileSync(
        path.join(dir, "VerisCallScreeningService.kt"),
        kotlinSource(pkg),
        "utf8",
      )
      console.log("[veris-call-screening] wrote VerisCallScreeningService.kt")
      return cfg
    },
  ])
}

/** Declare the service in the manifest with the system-only bind permission. */
function withCallScreeningManifest(config) {
  return withAndroidManifest(config, (cfg) => {
    const app = AndroidConfig.Manifest.getMainApplicationOrThrow(cfg.modResults)
    app.service = app.service ?? []

    if (app.service.some((s) => s.$?.["android:name"] === SERVICE_CLASS)) return cfg

    app.service.push({
      $: {
        "android:name": SERVICE_CLASS,
        "android:permission": "android.permission.BIND_SCREENING_SERVICE",
        "android:exported": "true",
      },
      "intent-filter": [
        {
          action: [{ $: { "android:name": "android.telecom.CallScreeningService" } }],
        },
      ],
    })
    return cfg
  })
}

function kotlinSource(pkg) {
  return `package ${pkg}

import android.telecom.Call
import android.telecom.CallScreeningService
import java.io.BufferedReader

/**
 * Screens incoming calls against a scam list bundled in the APK.
 *
 * Android gives a screening service only a few seconds to respond, so this
 * does no network I/O at all -- the list is read once from assets and cached.
 * A number we do not recognise is always allowed through: a fraud tool that
 * silently swallows calls is worse than one that does nothing.
 */
class VerisCallScreeningService : CallScreeningService() {

    companion object {
        /** Last 10 digits of every reported number. Loaded once per process. */
        @Volatile
        private var scamNumbers: Set<String>? = null

        /** India dials 10-digit subscriber numbers; ignore +91 / 0 prefixes. */
        fun normalise(raw: String?): String {
            val digits = (raw ?: "").filter { it.isDigit() }
            return if (digits.length > 10) digits.takeLast(10) else digits
        }
    }

    private fun numbers(): Set<String> {
        scamNumbers?.let { return it }
        val loaded = try {
            assets.open("veris_scam_numbers.txt").bufferedReader().use { reader: BufferedReader ->
                reader.readLines()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .map { normalise(it) }
                    .filter { it.length == 10 }
                    .toSet()
            }
        } catch (e: Exception) {
            // No list bundled, or unreadable: screen nothing rather than crash
            // the phone's call path.
            emptySet()
        }
        scamNumbers = loaded
        return loaded
    }

    override fun onScreenCall(callDetails: Call.Details) {
        val incoming = normalise(callDetails.handle?.schemeSpecificPart)
        val isScam = incoming.length == 10 && numbers().contains(incoming)

        val response = CallResponse.Builder()
            .setDisallowCall(isScam)
            .setRejectCall(isScam)
            // Keep it out of the call log only when we actually rejected it.
            .setSkipCallLog(isScam)
            .setSkipNotification(isScam)
            .build()

        respondToCall(callDetails, response)
    }
}
`
}

module.exports = function withCallScreening(config) {
  config = withScamNumberAsset(config)
  config = withCallScreeningSource(config)
  config = withCallScreeningManifest(config)
  return config
}
