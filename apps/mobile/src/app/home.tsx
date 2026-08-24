import { useEffect, useRef, useState } from "react"
import {
  ActivityIndicator,
  Image,
  Linking,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native"
import { router } from "expo-router"
import { useShareIntentContext } from "expo-share-intent"
import { LinearGradient } from "expo-linear-gradient"

import { API_BASE, check, health } from "../lib/api"
import { light } from "../lib/theme"
import { setLastResult } from "../lib/store"
import { triageOnDevice } from "../lib/ondevice"
import { checkForUpdate, type UpdateInfo } from "../lib/updates"
import * as ImagePicker from "expo-image-picker"
import { firstCandidate, textFromImage } from "../lib/ocr"

export default function Home() {
  const [input, setInput] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [engine, setEngine] = useState<string | null>(null)
  const [update, setUpdate] = useState<UpdateInfo | null>(null)
  const { hasShareIntent, shareIntent, resetShareIntent } = useShareIntentContext()
  // The share effect can fire more than once for one share. Without this the
  // same check lands in the tamper-evident ledger twice, which makes the
  // evidence trail look sloppy to anyone reading it.
  const lastHandled = useRef<string | null>(null)

  // Checked quietly on launch. A failure here must never get in the way of
  // someone trying to verify a message.
  useEffect(() => {
    checkForUpdate().then((info) => {
      if (info?.available) setUpdate(info)
    })
  }, [])

  useEffect(() => {
    health()
      .then((h) => setEngine(`engine ${h.engine_version} (${h.mode})`))
      .catch(() => setEngine("engine unreachable"))
  }, [])

  // A link shared from SMS, WhatsApp or a browser lands here and is checked
  // immediately -- the user should not have to press anything.
  useEffect(() => {
    if (!hasShareIntent) return

    // A shared image (a scam screenshot) -> read its text on-device, then
    // check the link / UPI id / number inside it with the same engine.
    const image = shareIntent.files?.find((f) => f.mimeType?.startsWith("image/"))
    if (image?.path && image.path !== lastHandled.current) {
      lastHandled.current = image.path
      void handleScreenshot(image.path)
      resetShareIntent()
      return
    }

    const shared = shareIntent.webUrl ?? shareIntent.text
    if (shared && shared !== lastHandled.current) {
      lastHandled.current = shared
      setInput(shared)
      void run(shared)
    }
    resetShareIntent()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasShareIntent])

  async function pickScreenshot() {
    // Android 13+ photo picker needs no permission; it returns one image uri.
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ["images"],
      quality: 1,
    })
    if (!result.canceled && result.assets[0]?.uri) {
      await handleScreenshot(result.assets[0].uri)
    }
  }

  async function handleScreenshot(uri: string) {
    setBusy(true)
    setError(null)
    try {
      const candidate = firstCandidate(await textFromImage(uri))
      if (!candidate) {
        setError("No link, UPI id, or phone number was found in that image.")
        return
      }
      setInput(candidate)
      await run(candidate)
    } catch {
      setError("Could not read text from that image.")
    } finally {
      setBusy(false)
    }
  }

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
    <View style={styles.root}>
      <LinearGradient
        colors={[light.bgMid, light.bg, light.white]}
        locations={[0, 0.22, 0.5]}
        style={StyleSheet.absoluteFill}
      />
      <ScrollView contentContainerStyle={styles.page} keyboardShouldPersistTaps="handled">
        {/* header */}
        <View style={styles.header}>
          <View style={styles.brand}>
            <Image source={require("../../assets/images/icon.png")} style={styles.brandLogo} />
            <Text style={styles.brandName}>Veris</Text>
          </View>
          <View style={styles.avatar}>
            <Text style={styles.avatarText}>S</Text>
          </View>
        </View>

        <Text style={styles.lede}>
          Paste a link, SMS, UPI id or phone number. Veris checks it against real
          sources and shows you every signal it used.
        </Text>

        <TextInput
          style={styles.input}
          placeholder="https://... or someone@ybl"
          placeholderTextColor={light.faint}
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

        {update && (
          <Pressable
            style={styles.update}
            onPress={() => void Linking.openURL(update.downloadUrl)}
            accessibilityRole="button"
          >
            <Text style={styles.updateTitle}>Update available: {update.latest}</Text>
            <Text style={styles.updateText}>
              You have {update.installed}. Tap to download, then open the file to
              install over the top -- you do not need to uninstall Veris.
            </Text>
          </Pressable>
        )}

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

        <Pressable style={styles.investigator} onPress={() => router.push("/email" as "/")}>
          <View style={{ flex: 1 }}>
            <Text style={styles.investigatorTitle}>Email Threat Forensics</Text>
            <Text style={styles.investigatorSub}>Analyze a suspicious email — trace origin, verify, attribute</Text>
          </View>
          <Text style={styles.investigatorArrow}>→</Text>
        </Pressable>

        <Pressable style={styles.secondary} onPress={() => router.push("/scan" as "/")}>
          <Text style={styles.secondaryText}>Scan a QR code</Text>
        </Pressable>

        <Pressable style={styles.secondary} onPress={pickScreenshot} disabled={busy}>
          <Text style={styles.secondaryText}>Check a screenshot</Text>
        </Pressable>

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
    </View>
  )
}

const shadow = {
  shadowColor: "#1e293b",
  shadowOpacity: 0.08,
  shadowRadius: 12,
  shadowOffset: { width: 0, height: 5 },
  elevation: 2,
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: light.white },
  page: { padding: 18, paddingTop: 60, gap: 14, flexGrow: 1 },
  header: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginBottom: 2 },
  brand: { flexDirection: "row", alignItems: "center", gap: 10 },
  brandLogo: { width: 36, height: 36, borderRadius: 11 },
  brandName: { fontSize: 22, fontWeight: "800", color: light.ink, letterSpacing: -0.5 },
  avatar: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: light.primary,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 2.5,
    borderColor: "#fff",
    ...shadow,
  },
  avatarText: { color: "#fff", fontSize: 18, fontWeight: "700" },
  lede: { color: light.muted, fontSize: 15, lineHeight: 22 },
  input: {
    backgroundColor: light.card,
    borderColor: light.line,
    borderWidth: 1,
    borderRadius: 16,
    color: light.ink,
    padding: 14,
    minHeight: 96,
    fontSize: 16,
    textAlignVertical: "top",
    ...shadow,
  },
  primary: {
    backgroundColor: light.primaryDark,
    borderRadius: 16,
    paddingVertical: 16,
    alignItems: "center",
    shadowColor: light.primary,
    shadowOpacity: 0.32,
    shadowRadius: 14,
    shadowOffset: { width: 0, height: 8 },
    elevation: 4,
  },
  pressed: { opacity: 0.85 },
  disabled: { opacity: 0.6 },
  primaryText: { color: "#fff", fontWeight: "700", fontSize: 16 },
  error: {
    backgroundColor: light.dangerBg,
    borderColor: "#fecaca",
    borderWidth: 1,
    borderRadius: 14,
    padding: 12,
  },
  errorText: { color: "#b91c1c", fontSize: 13, lineHeight: 19 },
  hint: {
    backgroundColor: light.card,
    borderColor: light.line,
    borderWidth: 1,
    borderRadius: 16,
    padding: 14,
    gap: 5,
    ...shadow,
  },
  hintTitle: { color: light.ink, fontWeight: "700", fontSize: 15 },
  hintText: { color: light.muted, fontSize: 14, lineHeight: 20 },
  secondary: {
    backgroundColor: light.card,
    borderColor: light.line,
    borderWidth: 1,
    borderRadius: 16,
    paddingVertical: 15,
    alignItems: "center",
    ...shadow,
  },
  secondaryText: { color: light.ink, fontWeight: "600", fontSize: 15 },
  investigator: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
    backgroundColor: "#eff6ff",
    borderColor: "#bfdbfe",
    borderWidth: 1.5,
    borderRadius: 16,
    padding: 16,
    ...shadow,
  },
  investigatorTitle: { color: light.primaryDark, fontWeight: "800", fontSize: 16 },
  investigatorSub: { color: "#3b82f6", fontSize: 12, marginTop: 2 },
  investigatorArrow: { color: light.primaryDark, fontSize: 20, fontWeight: "800" },
  footer: { color: light.faint, fontSize: 11, textAlign: "center", marginTop: 4 },
  update: {
    backgroundColor: "#eff6ff",
    borderColor: "#bfdbfe",
    borderWidth: 1,
    borderRadius: 14,
    padding: 13,
    gap: 4,
  },
  updateTitle: { color: light.primaryDark, fontWeight: "700", fontSize: 15 },
  updateText: { color: light.muted, fontSize: 13, lineHeight: 19 },
})
