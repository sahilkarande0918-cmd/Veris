import { useEffect, useState } from "react"
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native"
import { router } from "expo-router"
import { useShareIntentContext } from "expo-share-intent"

import { API_BASE, check, health } from "../lib/api"
import { colors } from "../lib/theme"
import { setLastResult } from "../lib/store"
import { triageOnDevice } from "../lib/ondevice"

export default function Home() {
  const [input, setInput] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [engine, setEngine] = useState<string | null>(null)
  const { hasShareIntent, shareIntent, resetShareIntent } = useShareIntentContext()

  useEffect(() => {
    health()
      .then((h) => setEngine(`engine ${h.engine_version} (${h.mode})`))
      .catch(() => setEngine("engine unreachable"))
  }, [])

  // A link shared from SMS, WhatsApp or a browser lands here and is checked
  // immediately -- the user should not have to press anything.
  useEffect(() => {
    if (!hasShareIntent) return
    const shared = shareIntent.webUrl ?? shareIntent.text
    if (shared) {
      setInput(shared)
      void run(shared)
    }
    resetShareIntent()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasShareIntent])

  async function run(raw: string) {
    const value = raw.trim()
    if (!value || busy) return
    setBusy(true)
    setError(null)
    try {
      const result = await check(value)
      setLastResult(result)
      router.push("/result")
    } catch (caught) {
      // The server is unreachable. Rather than failing, score it on the phone:
      // a weaker check, clearly labelled, beats no answer when someone is
      // standing at a counter deciding whether to pay.
      const local = triageOnDevice(value)
      setLastResult(local)
      setError(
        "Could not reach the Veris server, so this was checked on your phone instead. It is a lighter check -- run the full one when you have a connection.",
      )
      router.push("/result")
    } finally {
      setBusy(false)
    }
  }

  return (
    <ScrollView contentContainerStyle={styles.page} keyboardShouldPersistTaps="handled">
      <Text style={styles.lede}>
        Paste a link, SMS, UPI id or phone number. Veris checks it against real
        sources and shows you every signal it used.
      </Text>

      <TextInput
        style={styles.input}
        placeholder="https://... or someone@ybl"
        placeholderTextColor={colors.muted}
        value={input}
        onChangeText={setInput}
        multiline
        autoCapitalize="none"
        autoCorrect={false}
      />

      <Pressable
        style={({ pressed }) => [styles.primary, pressed && styles.pressed, busy && styles.disabled]}
        onPress={() => run(input)}
        disabled={busy}
        accessibilityRole="button"
      >
        {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.primaryText}>Check it</Text>}
      </Pressable>

      {error && (
        <View style={styles.error}>
          <Text style={styles.errorText}>{error}</Text>
        </View>
      )}

      <View style={styles.hint}>
        <Text style={styles.hintTitle}>Share straight into Veris</Text>
        <Text style={styles.hintText}>
          In any app, long-press a suspicious link and choose Share, then pick
          Veris. It is checked the moment it arrives.
        </Text>
      </View>

      <Pressable style={styles.secondary} onPress={() => router.push("/protect")}>
        <Text style={styles.secondaryText}>Protection settings</Text>
      </Pressable>

      <Pressable style={styles.secondary} onPress={() => router.push("/history")}>
        <Text style={styles.secondaryText}>Evidence ledger</Text>
      </Pressable>

      <Text style={styles.footer}>
        {engine ?? "checking engine..."}
        {"\n"}
        {API_BASE}
      </Text>
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  page: { padding: 18, gap: 14, backgroundColor: colors.bg, flexGrow: 1 },
  lede: { color: colors.muted, fontSize: 15, lineHeight: 22 },
  input: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    color: colors.text,
    padding: 14,
    minHeight: 96,
    fontSize: 16,
    textAlignVertical: "top",
  },
  primary: {
    backgroundColor: colors.accent,
    borderRadius: 12,
    paddingVertical: 15,
    alignItems: "center",
  },
  pressed: { opacity: 0.8 },
  disabled: { opacity: 0.6 },
  primaryText: { color: "#fff", fontWeight: "700", fontSize: 16 },
  error: {
    backgroundColor: "#3A1620",
    borderColor: colors.danger,
    borderWidth: 1,
    borderRadius: 12,
    padding: 12,
  },
  errorText: { color: "#FFD5D5", fontSize: 13, lineHeight: 19 },
  hint: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    padding: 14,
    gap: 5,
  },
  hintTitle: { color: colors.text, fontWeight: "700", fontSize: 15 },
  hintText: { color: colors.muted, fontSize: 14, lineHeight: 20 },
  secondary: {
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 13,
    alignItems: "center",
  },
  secondaryText: { color: colors.text, fontWeight: "600", fontSize: 15 },
  footer: { color: colors.muted, fontSize: 11, textAlign: "center", marginTop: 4 },
})
