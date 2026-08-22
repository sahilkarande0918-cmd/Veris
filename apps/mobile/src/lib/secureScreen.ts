/**
 * FLAG_SECURE for the evidence/report screens (Tier 3 #10).
 *
 * When enabled, Android blocks screenshots AND screen recording/mirroring while
 * the screen is mounted -- so a victim's fraud report or the evidence ledger
 * can't be captured by shoulder-surfing malware.
 *
 * OFF by default, because FLAG_SECURE also blacks the screen out in screen
 * recordings and when mirroring to a projector -- which would sabotage the demo
 * (the tamper-check on History is demo step 4). Turn it on for a real
 * deployment by setting, in app.json:  "extra": { "secureScreens": true }
 */
import Constants from "expo-constants"
import { allowScreenCaptureAsync, preventScreenCaptureAsync } from "expo-screen-capture"
import { useEffect } from "react"

export function useSecureScreen(): void {
  const enabled = Constants.expoConfig?.extra?.secureScreens === true
  useEffect(() => {
    if (!enabled) return
    preventScreenCaptureAsync()
    return () => {
      allowScreenCaptureAsync()
    }
  }, [enabled])
}
