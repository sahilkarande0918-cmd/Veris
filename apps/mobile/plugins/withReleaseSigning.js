/**
 * Expo config plugin: sign release builds with the real Veris keystore.
 *
 * Expo's default signs release with the DEBUG keystore, which cannot go to
 * Play and marks the app as untrusted. This points the release build at
 * `credentials/veris-release.keystore` instead.
 *
 * The keystore and its passwords live in `apps/mobile/credentials/`, which is
 * gitignored and deliberately OUTSIDE `android/` -- `prebuild --clean` deletes
 * android/, and a signing key you can regenerate is a signing key you have
 * already lost.
 *
 * With no credentials present this is a no-op and the build falls back to
 * debug signing, so a teammate can clone and build without the secret.
 */

const { withAppBuildGradle } = require("expo/config-plugins")
const fs = require("fs")
const path = require("path")

const CREDENTIALS_DIR = "credentials"
const PROPS_FILE = "keystore.properties"

function readCredentials(projectRoot) {
  const propsPath = path.join(projectRoot, CREDENTIALS_DIR, PROPS_FILE)
  if (!fs.existsSync(propsPath)) return null

  const props = {}
  for (const line of fs.readFileSync(propsPath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) continue
    const at = trimmed.indexOf("=")
    if (at > 0) props[trimmed.slice(0, at).trim()] = trimmed.slice(at + 1).trim()
  }

  const keystore = path.join(projectRoot, CREDENTIALS_DIR, props.VERIS_KEYSTORE_FILE ?? "")
  if (!props.VERIS_KEYSTORE_FILE || !fs.existsSync(keystore)) return null

  return {
    // Gradle is happier with forward slashes on Windows.
    storeFile: keystore.replace(/\\/g, "/"),
    storePassword: props.VERIS_KEYSTORE_PASSWORD ?? "",
    keyAlias: props.VERIS_KEY_ALIAS ?? "veris",
    keyPassword: props.VERIS_KEY_PASSWORD ?? props.VERIS_KEYSTORE_PASSWORD ?? "",
  }
}

module.exports = function withReleaseSigning(config) {
  return withAppBuildGradle(config, (cfg) => {
    const creds = readCredentials(cfg.modRequest.projectRoot)
    if (!creds) {
      console.warn(
        "[veris-signing] no credentials/keystore.properties found; release will use the DEBUG keystore",
      )
      return cfg
    }

    let gradle = cfg.modResults.contents

    if (!gradle.includes("verisRelease")) {
      // Add our config next to the existing debug one.
      gradle = gradle.replace(
        /signingConfigs\s*\{/,
        `signingConfigs {
        verisRelease {
            storeFile file('${creds.storeFile}')
            storePassword '${creds.storePassword}'
            keyAlias '${creds.keyAlias}'
            keyPassword '${creds.keyPassword}'
        }`,
      )
    }

    // Point the release buildType at it, replacing Expo's debug default.
    gradle = gradle.replace(
      /(release\s*\{[\s\S]*?)signingConfig\s+signingConfigs\.debug/,
      "$1signingConfig signingConfigs.verisRelease",
    )

    // Skip merging native debug symbols. There are ~166 .so files across two
    // ABIs and merging their symbols adds many minutes to every release build,
    // for a symbol file only useful when uploading to Play for crash reports.
    if (!gradle.includes("debugSymbolLevel")) {
      gradle = gradle.replace(
        /(release\s*\{)/,
        "$1\n            ndk { debugSymbolLevel 'none' }",
      )
    }

    cfg.modResults.contents = gradle
    console.log("[veris-signing] release: Veris keystore, native debug symbols skipped")
    return cfg
  })
}
