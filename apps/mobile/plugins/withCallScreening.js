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

/** Kotlin reserves some words, and Indian packages start with `in`. Escape them. */
const KOTLIN_KEYWORDS = new Set([
  "as", "break", "class", "continue", "do", "else", "false", "for", "fun", "if",
  "in", "interface", "is", "null", "object", "package", "return", "super", "this",
  "throw", "true", "try", "typealias", "typeof", "val", "var", "when", "while",
])

function kotlinPackage(pkg) {
  return pkg
    .split(".")
    .map((part) => (KOTLIN_KEYWORDS.has(part) ? "`" + part + "`" : part))
    .join(".")
}

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

    // Needed to post the caller-ID card on Android 13+ (harmless if the
    // notification-guard plugin already added it).
    const manifest = cfg.modResults.manifest
    manifest["uses-permission"] = manifest["uses-permission"] ?? []
    const hasPerm = manifest["uses-permission"].some(
      (p) => p.$?.["android:name"] === "android.permission.POST_NOTIFICATIONS",
    )
    if (!hasPerm) {
      manifest["uses-permission"].push({
        $: { "android:name": "android.permission.POST_NOTIFICATIONS" },
      })
    }
    return cfg
  })
}

function kotlinSource(pkg) {
  return `package ${kotlinPackage(pkg)}

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.telecom.Call
import android.telecom.CallScreeningService
import androidx.core.app.NotificationCompat
import java.io.BufferedReader

/**
 * Screens incoming calls against a scam list bundled in the APK and, like a
 * caller-ID app, shows a card on EVERY incoming call so the user sees Veris
 * checked it.
 *
 * Android gives a screening service only a few seconds to respond, so this does
 * no network I/O -- the list is read once from assets and cached. A number we
 * do not recognise is always allowed through (a fraud tool that silently
 * swallows calls is worse than one that does nothing); a reported number is
 * rejected AND flagged with a red alert. We only ever post our own
 * notification -- we never read the call log or the user's contacts.
 */
class VerisCallScreeningService : CallScreeningService() {

    companion object {
        private const val CHANNEL_ID = "veris_call_alerts"

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
        val raw = callDetails.handle?.schemeSpecificPart
        val incoming = normalise(raw)
        val isScam = incoming.length == 10 && numbers().contains(incoming)

        val response = CallResponse.Builder()
            .setDisallowCall(isScam)
            .setRejectCall(isScam)
            // Keep it out of the call log only when we actually rejected it.
            .setSkipCallLog(isScam)
            .setSkipNotification(isScam)
            .build()

        // Caller-ID card on every incoming call. Wrapped so a UI failure can
        // never break the phone's call path.
        try {
            alert(if (raw.isNullOrBlank()) "Unknown number" else raw, isScam)
        } catch (e: Exception) {
        }

        respondToCall(callDetails, response)
    }

    private fun alert(display: String, isScam: Boolean) {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Call alerts", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "Flags reported fraud numbers on incoming calls"
                }
            )
        }

        val title = if (isScam) "⚠️ Fraud call blocked" else "Veris checked this call"
        val body = if (isScam)
            display + " is a reported scam number. Veris rejected the call."
        else
            display + " is not in the reported-fraud list. Stay alert -- never share an OTP or pay on a call."

        val open = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val pending = PendingIntent.getActivity(
            this, display.hashCode(), open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .setColor(if (isScam) 0xFFDC2626.toInt() else 0xFF16A34A.toInt())
            .build()

        manager.notify(display.hashCode(), notification)
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
