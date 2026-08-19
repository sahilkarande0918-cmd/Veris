/**
 * Turning the notification guard on.
 *
 * Notification access is granted on a dedicated system settings screen with a
 * warning, never a routine permission prompt -- so all the app can do is send
 * the user there and explain honestly why it is asking.
 */

import { NativeModules, Platform } from "react-native"
import * as IntentLauncher from "expo-intent-launcher"

const NOTIFICATION_LISTENER_SETTINGS = "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"

export const isSupported = (): boolean => Platform.OS === "android"

/** Open the system screen where notification access is granted. */
export async function openNotificationAccessSettings(): Promise<boolean> {
  if (!isSupported()) return false
  try {
    await IntentLauncher.startActivityAsync(NOTIFICATION_LISTENER_SETTINGS)
    return true
  } catch {
    try {
      await IntentLauncher.startActivityAsync("android.settings.SETTINGS")
      return true
    } catch {
      return false
    }
  }
}

/**
 * Whether the guard is currently allowed to see notifications.
 *
 * ponytail: Android exposes this only through Settings.Secure, which needs
 * native code to read. Rather than ship a native module for one boolean, the
 * UI asks the user to confirm after returning from settings. Add the module if
 * we ever need to react to the state changing on its own.
 */
export function canReadNotifications(): "unknown" {
  void NativeModules
  return "unknown"
}
