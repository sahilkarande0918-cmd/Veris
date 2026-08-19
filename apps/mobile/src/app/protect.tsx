import { useState } from "react"
import { Alert, Pressable, ScrollView, StyleSheet, Text, View } from "react-native"

import {
  isSupported,
  openDefaultAppsSettings,
  requestCallScreeningRole,
  type RoleOutcome,
} from "../lib/callscreening"
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

  async function enableScreening() {
    const outcome = await requestCallScreeningRole()
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
  warn: { color: colors.warn, fontSize: 13 },
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
