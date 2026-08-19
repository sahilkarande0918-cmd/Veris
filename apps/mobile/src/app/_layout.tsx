import { Stack } from "expo-router"
import { StatusBar } from "expo-status-bar"
import { ShareIntentProvider } from "expo-share-intent"

import { colors } from "../lib/theme"

/**
 * ShareIntentProvider wraps the whole app so a link shared from any other app
 * is available on whichever screen is mounted. The intent filter that makes
 * Veris appear in Android's share sheet is declared by the expo-share-intent
 * config plugin in app.json -- never by hand-editing android/, which prebuild
 * regenerates.
 */
export default function RootLayout() {
  return (
    <ShareIntentProvider>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: colors.bg },
          headerTintColor: colors.text,
          headerTitleStyle: { fontWeight: "700" },
          contentStyle: { backgroundColor: colors.bg },
        }}
      >
        <Stack.Screen name="index" options={{ title: "Veris" }} />
        <Stack.Screen name="result" options={{ title: "Evidence" }} />
        <Stack.Screen name="report" options={{ title: "Report" }} />
        <Stack.Screen name="history" options={{ title: "Ledger" }} />
        <Stack.Screen name="protect" options={{ title: "Protection" }} />
      </Stack>
    </ShareIntentProvider>
  )
}
