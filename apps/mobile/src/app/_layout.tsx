import { useEffect } from "react"
import { router, Stack } from "expo-router"
import { StatusBar } from "expo-status-bar"
import { ShareIntentProvider } from "expo-share-intent"

import { loadEngineUrl } from "../lib/api"
import { colors } from "../lib/theme"

/**
 * ShareIntentProvider wraps the whole app so a link shared from any other app
 * is available on whichever screen is mounted. The intent filter that makes
 * Veris appear in Android's share sheet is declared by the expo-share-intent
 * config plugin in app.json -- never by hand-editing android/, which prebuild
 * regenerates.
 */
export default function RootLayout() {
  // Load any saved engine URL before the first API call.
  useEffect(() => {
    void loadEngineUrl()
  }, [])

  return (
    <ShareIntentProvider
      options={{
        // debug logs go to Metro, which is how we verify intake without a UI.
        debug: true,
        resetOnBackground: true,
        onResetShareIntent: () => router.replace({ pathname: "/home" }),
      }}
    >
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: colors.bg },
          headerTintColor: colors.text,
          headerTitleStyle: { fontWeight: "700" },
          contentStyle: { backgroundColor: colors.bg },
        }}
      >
        <Stack.Screen name="index" options={{ headerShown: false }} />
        <Stack.Screen name="home" options={{ title: "Veris" }} />
        <Stack.Screen name="result" options={{ title: "Evidence" }} />
        <Stack.Screen name="report" options={{ title: "Report" }} />
        <Stack.Screen name="history" options={{ title: "Ledger" }} />
        <Stack.Screen name="protect" options={{ title: "Protection" }} />
        <Stack.Screen name="scan" options={{ title: "Scan QR" }} />
      </Stack>
    </ShareIntentProvider>
  )
}
