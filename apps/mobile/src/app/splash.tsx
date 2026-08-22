/**
 * Animated launch screen (UI refresh).
 *
 * On open: the logo zooms in (0.6 -> 1.0) with a fade over ~0.7s on a
 * light-blue -> white ground, the Get Started button fades up, then it hands
 * off to Home. Kept under ~1.5s so the demo stays crisp. Pure presentation —
 * no verdict logic, no API calls.
 */
import { useEffect } from "react"
import { Image, Pressable, StyleSheet, Text, View } from "react-native"
import { router } from "expo-router"
import { LinearGradient } from "expo-linear-gradient"
import Animated, {
  Easing,
  useAnimatedStyle,
  useSharedValue,
  withDelay,
  withTiming,
} from "react-native-reanimated"

import { light } from "../lib/theme"

export default function Splash() {
  const scale = useSharedValue(0.6)
  const logoOpacity = useSharedValue(0)
  const ctaOpacity = useSharedValue(0)
  const ctaShift = useSharedValue(18)

  useEffect(() => {
    logoOpacity.value = withTiming(1, { duration: 600, easing: Easing.out(Easing.quad) })
    scale.value = withTiming(1, { duration: 720, easing: Easing.out(Easing.back(1.5)) })
    ctaOpacity.value = withDelay(560, withTiming(1, { duration: 480 }))
    ctaShift.value = withDelay(560, withTiming(0, { duration: 480, easing: Easing.out(Easing.quad) }))
  }, [])

  const logoStyle = useAnimatedStyle(() => ({
    opacity: logoOpacity.value,
    transform: [{ scale: scale.value }],
  }))
  const ctaStyle = useAnimatedStyle(() => ({
    opacity: ctaOpacity.value,
    transform: [{ translateY: ctaShift.value }],
  }))

  return (
    <View style={styles.root}>
      <LinearGradient
        colors={[light.bgTop, light.bgMid, light.bg, light.white]}
        locations={[0, 0.24, 0.5, 0.74]}
        style={StyleSheet.absoluteFill}
      />

      <View style={styles.center}>
        <Animated.Image
          source={require("../../assets/images/icon.png")}
          style={[styles.logo, logoStyle]}
        />
      </View>

      <Animated.View style={[styles.bottom, ctaStyle]}>
        <View style={styles.trustRow}>
          <Text style={styles.trust}>Works offline</Text>
          <View style={styles.dot} />
          <Text style={styles.trust}>On-device</Text>
        </View>
        <Pressable style={styles.cta} onPress={() => router.replace("/")}>
          <Text style={styles.ctaText}>Get Started</Text>
          <Text style={styles.ctaArrow}>→</Text>
        </Pressable>
      </Animated.View>
    </View>
  )
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: light.white },
  center: { flex: 1, alignItems: "center", justifyContent: "center" },
  logo: { width: 196, height: 196, borderRadius: 46 },
  bottom: { paddingHorizontal: 28, paddingBottom: 44, gap: 20, alignItems: "center" },
  trustRow: { flexDirection: "row", alignItems: "center", gap: 14 },
  trust: { fontSize: 12, fontWeight: "600", color: "#0f766e" },
  dot: { width: 4, height: 4, borderRadius: 2, backgroundColor: "#94a3b8" },
  cta: {
    width: "100%",
    height: 56,
    borderRadius: 16,
    backgroundColor: light.primaryDark,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 10,
  },
  ctaText: { color: "#fff", fontSize: 16, fontWeight: "700" },
  ctaArrow: { color: "#fff", fontSize: 18, fontWeight: "700" },
})
