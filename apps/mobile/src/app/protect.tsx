import { useState } from "react"
import { Alert, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native"

import {
  isSupported,
  openDefaultAppsSettings,
  requestCallScreeningRole,
  type RoleOutcome,
} from "../lib/callscreening"
import {
  openNotificationAccessSettings,
  requestPostNotifications,
} from "../lib/notificationguard"
import { getEngineUrl, setEngineUrl } from "../lib/api"
import { colors } from "../lib/theme"

const OUTCOME_TEXT: Record<RoleOutcome, string> = {
  granted: "Veris is now screening calls. Numbers on the reported list are rejected before your phone rings.",
  declined: "Not enabled. You can turn it on any time.",
  unsupported: "Call screening needs Android 10 or newer.",
  unavailable:
    "Your phone did not offer the choice. Some manufacturers reserve call screening for their own dialler -- open Default apps and set Veris as the Caller ID & spam app if it is listed.",
}

export default function Protect() {
  const [status, setStatus] = useState<string | null>(null)
  const [engineUrl, setEngineUrlInput] = useState<string>(getEngineUrl())

  async function enableScreening() {
    // The caller-ID card Veris shows on every call is a notification, so
    // without POST_NOTIFICATIONS Android silently drops it -- which looks like
    // "nothing happened". Ask for it as part of enabling screening.
    const canPost = await requestPostNotifications()
    const notifHint = canPost
      ? ""
      : " Also allow notifications for Veris (Settings → Apps → Veris → Notifications) so the call card can appear."

    const outcome = await requestCallScreeningRole()
    if (outcome === "granted") {
      setStatus(
        "Veris is screening calls." +
          notifHint +
          " Test it: call from a number that is NOT in your contacts — you'll see a Veris card, and reported scam numbers are rejected before your phone rings.",
      )
      return
    }
    if (outcome === "declined") {
      // Android returns 'declined' both when the user refuses AND when Veris
      // already holds the role (the dialog just closes). So never claim it's
      // off -- guide the user to verify by testing instead.
      setStatus(
        "If Android showed the caller-ID dialog, choose Veris. Already set Veris as the Caller ID & spam app in Settings? Then it's already on — test with a call from a number not in your contacts." +
          notifHint,
      )
      return
    }
    setStatus(OUTCOME_TEXT[outcome])
    if (outcome === "unavailable") {
      Alert.alert("Open settings?", "Set Veris as the Caller ID & spam app by hand?", [
        { text: "Not now", style: "cancel" },
        { text: "Open settings", onPress: () => void openDefaultAppsSettings() },
      ])
    }
  }

  return (
    <ScrollView contentContainerStyle={styles.page}>
      <Text style={styles.lede}>
        Veris checks what you send it. These add-ons let it warn you at the
        moment an attack arrives, without sending anything off your phone.
      </Text>

      <View style={[styles.card, styles.feature]}>
        <Text style={styles.title}>Engine URL</Text>
        <Text style={styles.body}>
          Where the full verdict engine runs. Must be an HTTPS address (a hosted
          URL) — plain HTTP is blocked for your safety. The on-device checks
          work even if this is unreachable.
        </Text>
        <TextInput
          style={styles.input}
          value={engineUrl}
          onChangeText={setEngineUrlInput}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          placeholder="https://your-engine.onrender.com"
          placeholderTextColor={colors.muted}
        />
        <Pressable
          style={({ pressed }) => [styles.primary, pressed && { opacity: 0.8 }]}
          onPress={async () => {
            await setEngineUrl(engineUrl)
            setStatus(`Engine set to ${getEngineUrl()}`)
          }}
        >
          <Text style={styles.primaryText}>Save engine URL</Text>
        </Pressable>
      </View>

      <View style={styles.card}>
        <Text style={styles.title}>Screen scam calls</Text>
        <Text style={styles.body}>
          When a number that is not in your contacts rings, Android gives Veris
          a few seconds to check it against a list of reported scam numbers
          stored on your phone. Matches are rejected before your phone rings.
        </Text>
        <Text style={styles.note}>
          The list is bundled into the app, so this works with no internet and
          no server. Veris never reads your call history: screening only ever
          sees the number currently calling.
        </Text>
        {!isSupported() && (
          <Text style={styles.warn}>Needs Android 10 or newer.</Text>
        )}
        <Pressable
          style={({ pressed }) => [styles.primary, pressed && { opacity: 0.8 }]}
          onPress={enableScreening}
          disabled={!isSupported()}
        >
          <Text style={styles.primaryText}>Enable call screening</Text>
        </Pressable>
        {status && <Text style={styles.status}>{status}</Text>}
      </View>

      <View style={[styles.card, styles.feature]}>
        <Text style={styles.title}>Warn me automatically</Text>
        <Text style={styles.body}>
          Veris can watch the notifications that arrive on this phone -- SMS,
          WhatsApp, email, anything -- and put a warning in your notification
          bar within a second when a message looks like a scam. Nothing to
          paste, nothing to share.
        </Text>
        <Text style={styles.note}>
          It never blocks, deletes or changes your messages. It only adds its
          own warning next to them.
        </Text>
        <Text style={styles.note}>
          Every message is judged on this phone. The text is scored and thrown
          away immediately -- it is never sent to our server or anywhere else,
          and it is never saved.
        </Text>
        <Text style={styles.warn}>
          Android will warn you that Veris can read all your notifications.
          That warning is correct, and you should take it seriously for any app.
          Ours are checked and discarded on the device; the code is in
          plugins/withNotificationGuard.js if you want to read it.
        </Text>
        <Pressable
          style={({ pressed }) => [styles.primary, pressed && { opacity: 0.8 }]}
          onPress={async () => {
            // Two separate grants. Without the first, Veris reads messages fine
            // and its warning is silently dropped -- which looks like a bug.
            const canPost = await requestPostNotifications()
            const opened = await openNotificationAccessSettings()
            setStatus(
              !canPost
                ? "Allow notifications for Veris first, otherwise its warnings cannot appear. Settings -> Apps -> Veris -> Notifications."
                : opened
                  ? "Find Veris in the list and turn it on. Then send yourself a test message."
                  : "Could not open the settings screen. Look for Notification access in Settings.",
            )
          }}
        >
          <Text style={styles.primaryText}>Turn on automatic warnings</Text>
        </Pressable>
      </View>

      <View style={styles.card}>
        <Text style={styles.title}>Offline scam triage</Text>
        <Text style={styles.body}>
          If the Veris server cannot be reached, the app still scores pasted or
          shared text on the phone itself, using the same kind of deterministic
          checks: known scam wording, fake lookalike web addresses, and UPI IDs
          on the reported list.
        </Text>
        <Text style={styles.note}>
          Always on. Nothing to enable, nothing to download.
        </Text>
      </View>

      <View style={styles.card}>
        <Text style={styles.title}>Reading your SMS automatically</Text>
        <Text style={styles.body}>
          Veris deliberately does not do this. Google Play only allows an app to
          read your messages if it replaces your messaging app entirely, and we
          are not willing to ask for that to check a link.
        </Text>
        <Text style={styles.note}>
          Share the message into Veris instead: long-press it, tap Share, choose
          Veris. Same result, and no app gets to read every message you receive.
        </Text>
      </View>
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  page: { padding: 18, gap: 12, backgroundColor: colors.bg, flexGrow: 1 },
  lede: { color: colors.muted, fontSize: 15, lineHeight: 22 },
  card: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    padding: 14,
    gap: 8,
  },
  title: { color: colors.text, fontWeight: "700", fontSize: 17 },
  body: { color: colors.text, fontSize: 14, lineHeight: 21 },
  note: { color: colors.muted, fontSize: 13, lineHeight: 19 },
  warn: { color: colors.warn, fontSize: 13, lineHeight: 19 },
  feature: { borderColor: colors.accent },
  input: {
    backgroundColor: colors.bg,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 10,
    color: colors.text,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 15,
  },
  primary: {
    backgroundColor: colors.accent,
    borderRadius: 10,
    paddingVertical: 13,
    alignItems: "center",
    marginTop: 4,
  },
  primaryText: { color: "#fff", fontWeight: "700", fontSize: 15 },
  status: { color: colors.safe, fontSize: 13, lineHeight: 19 },
})
