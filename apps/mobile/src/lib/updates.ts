/**
 * "A new version is available" -- checked against GitHub Releases.
 *
 * Android does not let an app outside the Play Store install its own update
 * silently, and that is deliberate: an app that could rewrite itself without
 * the user noticing is a malware primitive. So the most an honest sideloaded
 * app can do is notice, say so, and hand the user the download.
 *
 * What it DOES remove is the uninstall step. Every build is signed with the
 * same key (see plugins/withReleaseSigning.js), so a downloaded update
 * installs straight over the existing app and keeps its data.
 *
 * ponytail: the GitHub Releases API instead of expo-updates. OTA updates would
 * need EAS or a self-hosted update server, and cannot deliver native changes
 * anyway -- half our features are native. Swap to expo-updates if pushing JS
 * fixes mid-demo ever matters more than shipping native ones.
 */

import Constants from "expo-constants"

const RELEASES_API =
  "https://api.github.com/repos/sahilkarande0918-cmd/Veris/releases/latest"
const RELEASES_PAGE =
  "https://github.com/sahilkarande0918-cmd/Veris/releases/latest"

export interface UpdateInfo {
  available: boolean
  installed: string
  latest: string
  /** Direct .apk link when the release has one, else the releases page. */
  downloadUrl: string
  notes: string
}

/** "v1.2.3" / "1.2.3" -> [1, 2, 3]. Missing parts count as zero. */
function parseVersion(raw: string): number[] {
  return (raw ?? "")
    .trim()
    .replace(/^v/i, "")
    .split(".")
    .map((part) => Number.parseInt(part, 10))
    .map((n) => (Number.isFinite(n) ? n : 0))
}

/** True when `latest` is strictly newer than `installed`. */
export function isNewer(latest: string, installed: string): boolean {
  const a = parseVersion(latest)
  const b = parseVersion(installed)
  const length = Math.max(a.length, b.length)
  for (let i = 0; i < length; i++) {
    const left = a[i] ?? 0
    const right = b[i] ?? 0
    if (left !== right) return left > right
  }
  return false
}

export function installedVersion(): string {
  return Constants.expoConfig?.version ?? "0.0.0"
}

/**
 * Ask GitHub whether there is a newer release.
 *
 * Never throws: a failed check must not interrupt someone trying to verify a
 * suspicious message. Returns available:false on any problem.
 */
export async function checkForUpdate(): Promise<UpdateInfo | null> {
  const installed = installedVersion()
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 8000)
    const response = await fetch(RELEASES_API, {
      headers: { Accept: "application/vnd.github+json" },
      signal: controller.signal,
    })
    clearTimeout(timer)
    if (!response.ok) return null

    const release = (await response.json()) as {
      tag_name?: string
      body?: string
      assets?: { name?: string; browser_download_url?: string }[]
    }

    const latest = release.tag_name ?? ""
    if (!latest) return null

    const apk = release.assets?.find((a) => a.name?.toLowerCase().endsWith(".apk"))

    return {
      available: isNewer(latest, installed),
      installed,
      latest: latest.replace(/^v/i, ""),
      downloadUrl: apk?.browser_download_url ?? RELEASES_PAGE,
      notes: (release.body ?? "").trim().slice(0, 400),
    }
  } catch {
    return null
  }
}
