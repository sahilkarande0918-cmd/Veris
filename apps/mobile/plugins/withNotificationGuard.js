/**
 * Expo config plugin: automatic scam warnings from notifications.
 *
 * Registers a NotificationListenerService. Android hands it every notification
 * other apps post -- SMS, WhatsApp, Gmail, anything -- so Veris can check a
 * message the moment it arrives without the user pasting or sharing it, and
 * WITHOUT the restricted READ_SMS permission.
 *
 * Three rules this implementation holds to, because notification access is the
 * most privacy-sensitive thing an Android app can ask for:
 *
 *   1. Everything is judged on the device. Notification content is never sent
 *      anywhere, not even to our own engine.
 *   2. Nothing is blocked, dismissed, or altered. We only post our own warning
 *      alongside. The user's messages are theirs.
 *   3. Nothing is stored. The text is scored and dropped; only the verdict and
 *      which app it came from reach our notification.
 *
 * The user grants this on a dedicated system settings screen with a warning,
 * never a routine permission prompt.
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

const SERVICE_CLASS = ".VerisNotificationGuardService"

function withRulesAsset(config) {
  return withDangerousMod(config, [
    "android",
    (cfg) => {
      const repoRoot = path.resolve(cfg.modRequest.projectRoot, "..", "..")
      const source = path.join(repoRoot, "fixtures", "ondevice_rules.json")
      const assetsDir = path.join(cfg.modRequest.platformProjectRoot, "app", "src", "main", "assets")
      fs.mkdirSync(assetsDir, { recursive: true })

      if (!fs.existsSync(source)) {
        throw new Error("[veris-notification-guard] fixtures/ondevice_rules.json is missing")
      }
      // Minify: this is parsed on every notification.
      const rules = JSON.parse(fs.readFileSync(source, "utf8"))
      fs.writeFileSync(path.join(assetsDir, "veris_rules.json"), JSON.stringify(rules), "utf8")
      console.log("[veris-notification-guard] bundled ondevice_rules.json into assets")
      return cfg
    },
  ])
}

function withGuardSource(config) {
  return withDangerousMod(config, [
    "android",
    (cfg) => {
      const pkg = cfg.android?.package
      if (!pkg) throw new Error("[veris-notification-guard] android.package must be set")
      const dir = path.join(
        cfg.modRequest.platformProjectRoot,
        "app", "src", "main", "java", ...pkg.split("."),
      )
      fs.mkdirSync(dir, { recursive: true })
      fs.writeFileSync(path.join(dir, "VerisNotificationGuardService.kt"), kotlin(pkg), "utf8")
      console.log("[veris-notification-guard] wrote VerisNotificationGuardService.kt")
      return cfg
    },
  ])
}

function withGuardManifest(config) {
  return withAndroidManifest(config, (cfg) => {
    const app = AndroidConfig.Manifest.getMainApplicationOrThrow(cfg.modResults)
    app.service = app.service ?? []
    if (!app.service.some((s) => s.$?.["android:name"] === SERVICE_CLASS)) {
      app.service.push({
        $: {
          "android:name": SERVICE_CLASS,
          "android:permission": "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
          "android:exported": "false",
        },
        "intent-filter": [
          { action: [{ $: { "android:name": "android.service.notification.NotificationListenerService" } }] },
        ],
      })
    }
    // Needed to post our own warning on Android 13+.
    const manifest = cfg.modResults.manifest
    manifest["uses-permission"] = manifest["uses-permission"] ?? []
    const has = (n) => manifest["uses-permission"].some((p) => p.$?.["android:name"] === n)
    if (!has("android.permission.POST_NOTIFICATIONS")) {
      manifest["uses-permission"].push({ $: { "android:name": "android.permission.POST_NOTIFICATIONS" } })
    }
    return cfg
  })
}

function kotlin(pkg) {
  return `package ${kotlinPackage(pkg)}

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.util.Log
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.util.Locale

/**
 * Reads notifications from other apps and warns when one looks like a scam.
 *
 * Judged entirely on this device. Nothing is transmitted, nothing is stored,
 * and no notification is ever blocked or dismissed -- we only add our own.
 */
class VerisNotificationGuardService : NotificationListenerService() {

    private data class Finding(val label: String, val weight: Int, val source: String)

    companion object {
        private const val TAG = "VerisGuard"
        private const val CHANNEL_ID = "veris_scam_warnings"
        private const val MAX_TEXT = 1200

        /** Apps whose notifications are never worth scanning. */
        private val IGNORED_PREFIXES = listOf(
            "android", "com.android.systemui", "com.google.android.gms",
        )

        private val URL_RE = Regex("""(?:https?://|www\\.)[^\\s<>"']+""", RegexOption.IGNORE_CASE)
        private val VPA_RE = Regex("""[a-z0-9._-]{2,64}@[a-z][a-z0-9]{1,32}""", RegexOption.IGNORE_CASE)
        private val PHONE_RE = Regex("""(?:\\+?91[- ]?)?[6-9]\\d{9}""")
        private val IPV4_RE = Regex("""^\\d{1,3}(\\.\\d{1,3}){3}$""")
    }

    private var rules: JSONObject? = null
    /** Recently judged texts, so a re-posted notification is not re-warned. */
    private val recentlySeen = object : LinkedHashMap<Int, Long>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, Long>?): Boolean = size > 64
    }

    private fun rules(): JSONObject {
        rules?.let { return it }
        val loaded = try {
            assets.open("veris_rules.json").bufferedReader().use { JSONObject(it.readText()) }
        } catch (e: Exception) {
            JSONObject()
        }
        rules = loaded
        return loaded
    }

    override fun onListenerConnected() {
        Log.i(TAG, "connected; rules keys=" + rules().length())
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        try {
            screen(sbn)
        } catch (e: Exception) {
            // Never let a parsing bug take down the notification pipeline.
            Log.e(TAG, "screen failed", e)
        }
    }

    private fun screen(sbn: StatusBarNotification) {
        val pkg = sbn.packageName ?: return
        if (pkg == packageName) return
        if (IGNORED_PREFIXES.any { pkg == it || pkg.startsWith("\$it.") }) return
        if (sbn.isOngoing) return

        val extras = sbn.notification?.extras ?: return
        val parts = listOfNotNull(
            extras.getCharSequence("android.title")?.toString(),
            extras.getCharSequence("android.text")?.toString(),
            extras.getCharSequence("android.bigText")?.toString(),
        )
        val text = parts.joinToString(" ").take(MAX_TEXT)
        Log.d(TAG, "from=" + pkg + " len=" + text.length)
        if (text.isBlank()) return

        val key = text.hashCode()
        val now = System.currentTimeMillis()
        val last = recentlySeen[key]
        if (last != null && now - last < 60_000) return
        recentlySeen[key] = now

        val findings = judge(text)
        Log.d(TAG, "findings=" + findings.size + " " + findings.joinToString { it.label })
        if (findings.isEmpty()) return

        val score = minOf(100, findings.sumOf { it.weight })
        val thresholds = rules().optJSONObject("thresholds")
        val scamAt = thresholds?.optInt("likely_scam", 60) ?: 60
        val suspectAt = thresholds?.optInt("suspicious", 30) ?: 30
        Log.d(TAG, "score=" + score + " scamAt=" + scamAt + " suspectAt=" + suspectAt)
        if (score < suspectAt) return

        warn(
            appLabel = labelOf(pkg),
            likelyScam = score >= scamAt,
            score = score,
            findings = findings,
            text = text,
        )
    }

    /** Deterministic checks. Same shape as the server: each returns its source. */
    private fun judge(raw: String): List<Finding> {
        val r = rules()
        if (r.length() == 0) return emptyList()
        val text = raw.lowercase(Locale.ROOT)
        val w = r.optJSONObject("weights") ?: JSONObject()
        val found = mutableListOf<Finding>()

        // 1. wording
        val phrases = r.optJSONArray("scam_phrases")
        var wording = 0
        val labels = mutableListOf<String>()
        if (phrases != null) {
            for (i in 0 until phrases.length()) {
                val p = phrases.optJSONObject(i) ?: continue
                val re = try { Regex(p.optString("pattern"), RegexOption.IGNORE_CASE) } catch (e: Exception) { continue }
                if (re.containsMatchIn(text)) {
                    wording += p.optInt("weight", 15)
                    labels.add(p.optString("label"))
                }
            }
        }
        if (wording > 0) {
            found.add(Finding(labels.joinToString("; "), minOf(w.optInt("scam_wording_cap", 50), wording), "wording"))
        }

        // 2. reported UPI id
        val vpas = r.optJSONArray("reported_vpas")
        if (vpas != null) {
            val hits = VPA_RE.findAll(text).map { it.value }.toSet()
            for (i in 0 until vpas.length()) {
                if (hits.contains(vpas.optString(i).lowercase(Locale.ROOT))) {
                    found.add(Finding("UPI id reported for fraud", w.optInt("reported_vpa", 70), "reported list"))
                    break
                }
            }
        }

        // 3. the URL, if there is one
        val url = URL_RE.find(raw)?.value
        if (url != null) {
            val host = hostOf(url)
            val brands = r.optJSONObject("brand_domains")
            val isKnownBrand = brands?.has(host) == true

            val blocked = r.optJSONArray("blocked_hosts")
            if (blocked != null) {
                for (i in 0 until blocked.length()) {
                    if (blocked.optString(i).equals(host, ignoreCase = true)) {
                        found.add(Finding("link is on a scam blocklist", w.optInt("blocklist_hit", 70), "blocklist"))
                        break
                    }
                }
            }

            if (!isKnownBrand && brands != null) {
                userinfoOf(url)?.let { info ->
                    val keys = brands.keys()
                    while (keys.hasNext()) {
                        val d = keys.next()
                        if (info.contains(d) || info.contains(d.substringBefore("."))) {
                            found.add(Finding("link hides its real address behind '@'", w.optInt("userinfo_deception", 60), "link structure"))
                            break
                        }
                    }
                }

                val keys = brands.keys()
                while (keys.hasNext()) {
                    val d = keys.next()
                    if ((host.contains("\$d.") || host.startsWith(brandLabel(d) + ".")) && !host.endsWith(d)) {
                        found.add(Finding("looks like \${brands.optString(d)} but is a different site", w.optInt("brand_as_subdomain", 60), "link structure"))
                        break
                    }
                }

                if (host.any { it.code > 127 } || host.contains("xn--")) {
                    found.add(Finding("web address uses lookalike characters", w.optInt("non_english_host", 55), "character set"))
                }
                if (IPV4_RE.matches(host)) {
                    found.add(Finding("link points at a raw IP address", w.optInt("ip_address_host", 45), "link structure"))
                }
            }
        }

        // 4. sender number on the reported list
        val numbers = r.optJSONArray("reported_numbers")
        if (numbers != null) {
            val seen = PHONE_RE.findAll(raw).map { it.value.filter { c -> c.isDigit() }.takeLast(10) }.toSet()
            for (i in 0 until numbers.length()) {
                val n = numbers.optString(i).filter { it.isDigit() }.takeLast(10)
                if (seen.contains(n)) {
                    found.add(Finding("number reported for fraud", w.optInt("reported_number", 70), "reported list"))
                    break
                }
            }
        }
        return found
    }

    private fun brandLabel(domain: String) = domain.substringBefore(".")

    private fun hostOf(url: String): String {
        val afterScheme = if (url.contains("://")) url.substringAfter("://") else url
        val authority = afterScheme.substringBefore("/").substringBefore("?").substringBefore("#")
        val hostPart = if (authority.contains("@")) authority.substringAfterLast("@") else authority
        val host = hostPart.substringBefore(":").lowercase(Locale.ROOT)
        return if (host.startsWith("www.")) host.substring(4) else host
    }

    private fun userinfoOf(url: String): String? {
        val afterScheme = if (url.contains("://")) url.substringAfter("://") else url
        val authority = afterScheme.substringBefore("/").substringBefore("?").substringBefore("#")
        return if (authority.contains("@")) authority.substringBeforeLast("@").lowercase(Locale.ROOT) else null
    }

    private fun labelOf(pkg: String): String = try {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
    } catch (e: Exception) {
        pkg
    }

    private fun warn(appLabel: String, likelyScam: Boolean, score: Int, findings: List<Finding>, text: String) {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Scam warnings", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "Warns when a message on this phone looks like a scam"
                }
            )
        }

        val title = if (likelyScam) "Likely scam in \$appLabel" else "Suspicious message in \$appLabel"
        val why = findings.joinToString("; ") { it.label }
        val body = "\$why. Do not share an OTP or pay. Tap to see the evidence."

        // Tapping opens Veris with the text so the user gets the full check.
        val open = Intent(this, MainActivity::class.java).apply {
            action = Intent.ACTION_SEND
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val pending = PendingIntent.getActivity(
            this, text.hashCode(), open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()

        manager.notify(text.hashCode(), notification)
        Log.i(TAG, "warning posted: " + title)
    }
}
`
}

module.exports = function withNotificationGuard(config) {
  config = withRulesAsset(config)
  config = withGuardSource(config)
  config = withGuardManifest(config)
  return config
}
