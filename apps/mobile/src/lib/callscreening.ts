/**
 * Asking Android to make Veris the call screener.
 *
 * ponytail: no custom native module. RoleManager.createRequestRoleIntent()
 * just builds an intent with a well-known action and extra, so
 * expo-intent-launcher can fire the same thing directly. Write a native
 * module only if we ever need to *read back* whether the role is held.
 */

import { Platform } from "react-native"
import * as IntentLauncher from "expo-intent-launcher"

const REQUEST_ROLE = "android.app.role.action.REQUEST_ROLE"
const EXTRA_ROLE_NAME = "android.app.role.extra.ROLE_NAME"
const ROLE_CALL_SCREENING = "android.app.role.CALL_SCREENING"

/** CallScreeningService landed in Android 10 (API 29). */
export const isSupported = (): boolean =>
  Platform.OS === "android" && Number(Platform.Version) >= 29

export type RoleOutcome = "granted" | "declined" | "unsupported" | "unavailable"

/**
 * Prompt the user to make Veris the call screener.
 *
 * Android decides whether to show the dialog at all -- some OEM builds
 * reserve the role for their own dialler, so "unavailable" is a normal
 * outcome and not an error.
 */
export async function requestCallScreeningRole(): Promise<RoleOutcome> {
  if (!isSupported()) return "unsupported"
  try {
    const result = await IntentLauncher.startActivityAsync(REQUEST_ROLE, {
      extra: { [EXTRA_ROLE_NAME]: ROLE_CALL_SCREENING },
    })
    // resultCode 1 == Activity.RESULT_OK
    return result.resultCode === 1 ? "granted" : "declined"
  } catch {
    return "unavailable"
  }
}

/** Fallback: the system screen where the role can be granted by hand. */
export async function openDefaultAppsSettings(): Promise<void> {
  try {
    await IntentLauncher.startActivityAsync("android.settings.MANAGE_DEFAULT_APPS_SETTINGS")
  } catch {
    await IntentLauncher.startActivityAsync("android.settings.SETTINGS")
  }
}
