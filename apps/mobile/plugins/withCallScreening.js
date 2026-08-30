/**
 * Expo config plugin: Android caller-ID for fraud calls.
 *
 * Two pieces, generated at prebuild time (nothing hand-edited into android/,
 * because prebuild regenerates it):
 *
 *   1. VerisCallReceiver -- a PHONE_STATE BroadcastReceiver that fires on EVERY
 *      incoming call (contacts included) and posts a caller-ID card: a red
 *      "likely fraud" card WITH THE REASON for numbers on the bundled reported-
 *      scam list, a neutral "checked" card otherwise. It NEVER blocks the call.
 *      Reading the incoming number needs READ_CALL_LOG on Android 9+, so this
 *      is a SIDELOAD-ONLY capability (Play restricts READ_CALL_LOG), matching
 *      the project's stance on SMS screening.
 *
 *   2. VerisCallScreeningService -- kept only so the "call screener" role the
 *      user granted stays valid; it now ALLOWS every call and blocks nothing.
 *      The visible card comes from the receiver, so there is one card per call.
 *
 * Everything is judged on the device against a bundled list. No network, no
 * server, and the call log is never read beyond the single ringing number.
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
const RECEIVER_CLASS = ".VerisCallReceiver"

/** Bundle the scam-number list into the APK as an asset. */
function withScamNumberAsset(config) {
  return withDangerousMod(config, [
    "android",
    (cfg) => {
      const repoRoot = path.resolve(cfg.modRequest.projectRoot, "..", "..")
      const source = path.join(repoRoot, "fixtures", "scam_numbers.txt")
      const assetsDir = path.join(
        cfg.modRequest.platformProjectRoot, "app", "src", "main", "assets",
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

/** Write both Kotlin sources into the generated Android project. */
function withKotlinSources(config) {
  return withDangerousMod(config, [
    "android",
    (cfg) => {
      const pkg = cfg.android?.package
      if (!pkg) throw new Error("[veris-call-screening] android.package must be set in app.json")
      const dir = path.join(
        cfg.modRequest.platformProjectRoot, "app", "src", "main", "java", ...pkg.split("."),
      )
      fs.mkdirSync(dir, { recursive: true })
      fs.writeFileSync(path.join(dir, "VerisCallScreeningService.kt"), screeningSource(pkg), "utf8")
      fs.writeFileSync(path.join(dir, "VerisCallReceiver.kt"), receiverSource(pkg), "utf8")
      console.log("[veris-call-screening] wrote VerisCallScreeningService.kt + VerisCallReceiver.kt")
      return cfg
    },
  ])
}

/** Declare the service + receiver + the permissions the card needs. */
function withCallManifest(config) {
  return withAndroidManifest(config, (cfg) => {
    const app = AndroidConfig.Manifest.getMainApplicationOrThrow(cfg.modResults)

    app.service = app.service ?? []
    if (!app.service.some((s) => s.$?.["android:name"] === SERVICE_CLASS)) {
      app.service.push({
        $: {
          "android:name": SERVICE_CLASS,
          "android:permission": "android.permission.BIND_SCREENING_SERVICE",
          "android:exported": "true",
        },
        "intent-filter": [
          { action: [{ $: { "android:name": "android.telecom.CallScreeningService" } }] },
        ],
      })
    }

    app.receiver = app.receiver ?? []
    if (!app.receiver.some((r) => r.$?.["android:name"] === RECEIVER_CLASS)) {
      app.receiver.push({
        $: { "android:name": RECEIVER_CLASS, "android:exported": "true" },
        "intent-filter": [
          { action: [{ $: { "android:name": "android.intent.action.PHONE_STATE" } }] },
        ],
      })
    }

    const manifest = cfg.modResults.manifest
    manifest["uses-permission"] = manifest["uses-permission"] ?? []
    const has = (n) => manifest["uses-permission"].some((p) => p.$?.["android:name"] === n)
    for (const perm of [
      "android.permission.POST_NOTIFICATIONS",
      "android.permission.READ_PHONE_STATE",
      "android.permission.READ_CALL_LOG",
    ]) {
      if (!has(perm)) manifest["uses-permission"].push({ $: { "android:name": perm } })
    }
    return cfg
  })
}

function screeningSource(pkg) {
  return `package ${kotlinPackage(pkg)}

import android.telecom.Call
import android.telecom.CallScreeningService

/**
 * Kept only so the call-screener role the user granted stays valid. It never
 * blocks anything -- the visible caller-ID card is posted by VerisCallReceiver,
 * which fires for every call. Allowing here guarantees Veris cannot swallow a
 * call the user wanted.
 */
class VerisCallScreeningService : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        respondToCall(callDetails, CallResponse.Builder().build())
    }
}
`
}

function receiverSource(pkg) {
  return `package ${kotlinPackage(pkg)}

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.telephony.TelephonyManager
import androidx.core.app.NotificationCompat
import java.io.BufferedReader

/**
 * Posts a caller-ID card on every incoming call. Red "likely fraud" WITH the
 * reason for numbers on the bundled reported-scam list, neutral otherwise.
 * Never blocks the call. Judged entirely on the device.
 */
class VerisCallReceiver : BroadcastReceiver() {

    companion object {
        private const val CHANNEL_ID = "veris_call_alerts"
        private const val CARD_ID = 1001
        @Volatile private var scamNumbers: Set<String>? = null
        @Volatile private var lastKey: String? = null

        fun normalise(raw: String?): String {
            val digits = (raw ?: "").filter { it.isDigit() }
            return if (digits.length > 10) digits.takeLast(10) else digits
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "android.intent.action.PHONE_STATE") return
        val state = intent.getStringExtra(TelephonyManager.EXTRA_STATE)
        if (state != TelephonyManager.EXTRA_STATE_RINGING) return
        val raw = intent.getStringExtra(TelephonyManager.EXTRA_INCOMING_NUMBER)
        val key = normalise(raw)
        // PHONE_STATE can fire several times for one ring -- de-dupe.
        if (key.isNotEmpty() && key == lastKey) return
        lastKey = key
        try {
            postCard(context, if (raw.isNullOrBlank()) "Unknown number" else raw, key)
        } catch (e: Exception) {
        }
    }

    private fun numbers(context: Context): Set<String> {
        scamNumbers?.let { return it }
        val loaded = try {
            context.assets.open("veris_scam_numbers.txt").bufferedReader().use { r: BufferedReader ->
                r.readLines().map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .map { normalise(it) }.filter { it.length == 10 }.toSet()
            }
        } catch (e: Exception) {
            emptySet()
        }
        scamNumbers = loaded
        return loaded
    }

    private fun postCard(context: Context, display: String, key: String) {
        val isScam = key.length == 10 && numbers(context).contains(key)
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Call alerts", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "Flags reported fraud numbers on incoming calls"
                }
            )
        }

        val title: String
        val body: String
        if (isScam) {
            title = "⚠️ Likely fraud call"
            body = display +
                " is on Veris's reported-scam list (reported for OTP / KYC / payment fraud)." +
                " Veris did NOT block it — do not share an OTP, make a payment, or follow instructions."
        } else {
            title = "Veris checked this call"
            body = display +
                " is not on the reported-fraud list. Stay alert — never share an OTP or pay on a call."
        }

        val open = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val pending = PendingIntent.getActivity(
            context, CARD_ID, open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val card = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setAutoCancel(true)
            .setOngoing(false)
            .setContentIntent(pending)
            .setColor(if (isScam) 0xFFDC2626.toInt() else 0xFF16A34A.toInt())
            .build()

        manager.notify(CARD_ID, card)
    }
}
`
}

module.exports = function withCallScreening(config) {
  config = withScamNumberAsset(config)
  config = withKotlinSources(config)
  config = withCallManifest(config)
  return config
}
