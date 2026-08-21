import { useRef, useState } from "react"
import { ActivityIndicator, Pressable, StyleSheet, Text, View } from "react-native"
import { CameraView, useCameraPermissions } from "expo-camera"
import { router } from "expo-router"

import { checkQr } from "../lib/api"
import { triageOnDevice } from "../lib/ondevice"
import { setLastResult } from "../lib/store"
import { colors } from "../lib/theme"

/**
 * Point the phone at a QR code; the camera decodes it on-device and the
 * decoded payload runs through the SAME verdict engine as every other intake.
 * A UPI QR is judged on the payee that receives the money, not the name it
 * claims.
 */
export default function Scan() {
  const [permission, requestPermission] = useCameraPermissions()
  const [busy, setBusy] = useState(false)
  // One scan per visit: the camera fires onBarcodeScanned repeatedly.
  const handled = useRef(false)

  async function onScanned(payload: string) {
    if (handled.current || busy) return
    handled.current = true
    setBusy(true)
    try {
      const result = await checkQr(payload.trim())
      setLastResult(result)
      router.replace("/result")
    } catch {
      // Engine unreachable: judge the payload on the phone, clearly labelled.
      setLastResult(triageOnDevice(payload.trim()))
      router.replace("/result")
    } finally {
      setBusy(false)
    }
  }

  if (!permission) {
    return (
      <View style={styles.center}>
        <ActivityIndicator color={colors.accent} />
      </View>
    )
  }

  if (!permission.granted) {
    return (
      <View style={styles.center}>
        <Text style={styles.title}>Camera access</Text>
        <Text style={styles.body}>
          Veris needs the camera only to read a QR code you point it at. It does
          not record or upload anything.
        </Text>
        <Pressable style={styles.primary} onPress={requestPermission}>
          <Text style={styles.primaryText}>Allow camera</Text>
        </Pressable>
      </View>
    )
  }

  return (
    <View style={styles.fill}>
      <CameraView
        style={StyleSheet.absoluteFill}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
        onBarcodeScanned={busy ? undefined : (e) => void onScanned(e.data)}
      />
      <View style={styles.overlay} pointerEvents="none">
        <View style={styles.frame} />
        <Text style={styles.hint}>
          {busy ? "Checking..." : "Point at a QR code"}
        </Text>
      </View>
      {busy && (
        <View style={styles.checking}>
          <ActivityIndicator color="#fff" />
        </View>
      )}
    </View>
  )
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: "#000" },
  center: { flex: 1, backgroundColor: colors.bg, padding: 24, justifyContent: "center", gap: 12 },
  title: { color: colors.text, fontSize: 20, fontWeight: "700" },
  body: { color: colors.muted, fontSize: 15, lineHeight: 22 },
  overlay: { ...StyleSheet.absoluteFill as object, alignItems: "center", justifyContent: "center", gap: 20 },
  frame: {
    width: 230,
    height: 230,
    borderColor: colors.accent,
    borderWidth: 3,
    borderRadius: 20,
    backgroundColor: "transparent",
  },
  hint: { color: "#fff", fontSize: 16, fontWeight: "600", textShadowColor: "#000", textShadowRadius: 6 },
  checking: { ...StyleSheet.absoluteFill as object, alignItems: "center", justifyContent: "center" },
  primary: { backgroundColor: colors.accent, borderRadius: 12, paddingVertical: 14, alignItems: "center", marginTop: 8 },
  primaryText: { color: "#fff", fontWeight: "700", fontSize: 16 },
})
