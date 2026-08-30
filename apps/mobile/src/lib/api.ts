/**
 * Client for the Veris verdict engine.
 *
 * The types below mirror `packages/shared/verdict.ts`, which is the source of
 * truth. Metro cannot resolve modules outside the app directory without
 * monorepo config, so they are duplicated deliberately -- if you change the
 * schema, change both.
 */

export type Verdict = "safe" | "suspicious" | "likely_scam"
export type SubjectType = "url" | "domain" | "phone" | "upi" | "apk_hash" | "email"

export interface Signal {
  id: string
  source: string
  value: string
  observed_at: string
  weight: number
}

export interface Explanation {
  english: string
  regional: string
  language: string
  generated_by: string
}

export interface VerdictResult {
  subject: { type: SubjectType; value: string }
  verdict: Verdict
  score: number
  signals: Signal[]
  rules_fired: string[]
  engine_version: string
  generated_at: string
  explanation?: Explanation | null
}

export type EmailClass = "legitimate" | "suspicious" | "impersonated" | "phishing" | "fraud-related"

export interface EmailForensics {
  from_name?: string
  from_addr?: string
  from_domain?: string
  to?: string
  return_path?: string
  reply_to?: string
  subject?: string
  message_id?: string
  auth_results: Record<string, string>
  originating_ip?: string | null
  geo?: { country?: string; country_code?: string; city?: string; org?: string; isp?: string; asn?: string }
  domain_intel?: { registrar?: string; age_days?: number | null; mx?: string[]; name_servers?: string[] }
  received_hops?: number
  links?: string[]
  classification: EmailClass
  pii_masked?: boolean
}

export interface EmailResult extends VerdictResult {
  email_forensics: EmailForensics
  case_file?: Record<string, unknown>
}

export interface LedgerEvent {
  seq: number
  recorded_at: string
  event_type: string
  payload: Record<string, unknown>
  prev_hash: string
  hash: string
}

export interface ChainStatus {
  ok: boolean
  count: number
  broken_at: number | null
  reason: string
  head_hash: string | null
  head_signature: string | null
  signing_key: string
}

import * as SecureStore from "expo-secure-store"

/**
 * The engine the app talks to. Resolution order:
 *   1. a URL the user saved in the app (Protection -> Engine URL)
 *   2. the value baked in at build time (EXPO_PUBLIC_VERIS_API)
 *   3. a localhost default (USB dev)
 *
 * Making it user-settable means one APK works against any engine -- a laptop
 * on the same Wi-Fi, or a public cloud URL -- with no rebuild. If the engine
 * is unreachable, callers already fall back to on-device triage.
 */
const BUILT_IN_BASE = process.env.EXPO_PUBLIC_VERIS_API ?? "http://127.0.0.1:8000"
const ENGINE_URL_KEY = "veris.engineUrl"

let currentBase = BUILT_IN_BASE
export const API_BASE = BUILT_IN_BASE // kept for the Home footer display

/** Load any saved engine URL at app start. Call once. */
export async function loadEngineUrl(): Promise<string> {
  try {
    const saved = await SecureStore.getItemAsync(ENGINE_URL_KEY)
    if (saved && saved.trim()) currentBase = saved.trim()
  } catch {
    // storage unavailable -> stick with the built-in default
  }
  return currentBase
}

export function getEngineUrl(): string {
  return currentBase
}

/** Save a user-entered engine URL and use it immediately. */
export async function setEngineUrl(url: string): Promise<void> {
  const cleaned = url.trim().replace(/\/+$/, "")
  currentBase = cleaned || BUILT_IN_BASE
  try {
    if (cleaned) await SecureStore.setItemAsync(ENGINE_URL_KEY, cleaned)
    else await SecureStore.deleteItemAsync(ENGINE_URL_KEY)
  } catch {
    // best effort; the in-memory value still applies for this session
  }
}

// A warm engine answers in well under a second, so abort a dead call quickly.
// The hosted engine (Render free tier) sleeps after idle and its first wake can
// take 30-50s, so on a timeout we retry ONCE with a much longer budget before
// giving up to on-device triage.
const TIMEOUT_MS = 15000
const COLD_START_MS = 55000

// --- Per-device API token (Tier 2 #7) -------------------------------------
// The engine issues a stateless token per device. We register once per engine
// URL and attach it as a bearer token. If the engine has no /auth/device (older
// build) or auth is off, registration just no-ops and calls proceed tokenless.
const DEVICE_ID_KEY = "veris.deviceId"
const TOKEN_KEY = "veris.token"
const TOKEN_BASE_KEY = "veris.tokenBase"
let deviceId: string | null = null
const tokenByBase: Record<string, string> = {}

function freshId(): string {
  return `dev-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 12)}`
}

async function getDeviceId(): Promise<string> {
  if (deviceId) return deviceId
  try {
    let id = await SecureStore.getItemAsync(DEVICE_ID_KEY)
    if (!id) {
      id = freshId()
      await SecureStore.setItemAsync(DEVICE_ID_KEY, id)
    }
    deviceId = id
  } catch {
    deviceId = deviceId ?? freshId()
  }
  return deviceId
}

async function ensureToken(base: string): Promise<string | null> {
  if (tokenByBase[base]) return tokenByBase[base]
  // Reuse a token persisted (Keystore-backed) for this same engine across launches.
  try {
    const savedBase = await SecureStore.getItemAsync(TOKEN_BASE_KEY)
    const savedToken = await SecureStore.getItemAsync(TOKEN_KEY)
    if (savedBase === base && savedToken) {
      tokenByBase[base] = savedToken
      return savedToken
    }
  } catch {
    // secure storage unavailable -> fall through to (re)register
  }
  try {
    const id = await getDeviceId()
    // Own short timeout: this runs before the main request, so a cold/hung
    // /auth/device must never block or poison the actual /check call. The token
    // is optional (auth_required=false) -- proceed tokenless if it doesn't answer.
    const ctl = new AbortController()
    const t = setTimeout(() => ctl.abort(), 8000)
    let res: Response
    try {
      res = await fetch(`${base}/auth/device`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: id }),
        signal: ctl.signal,
      })
    } finally {
      clearTimeout(t)
    }
    if (!res.ok) return null // older engine or unreachable: proceed tokenless
    const data = await res.json()
    if (data?.token) {
      tokenByBase[base] = data.token
      try {
        await SecureStore.setItemAsync(TOKEN_KEY, data.token)
        await SecureStore.setItemAsync(TOKEN_BASE_KEY, base)
      } catch {
        // non-fatal: the in-memory token still serves this session
      }
      return data.token
    }
  } catch {
    // registration failed: proceed tokenless; on-device fallback still covers it
  }
  return null
}

async function request<T>(
  path: string,
  init?: RequestInit,
  timeoutMs: number = TIMEOUT_MS,
  isRetry = false,
): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    // FormData sets its own multipart Content-Type (with a boundary); forcing
    // JSON would corrupt the upload. JSON callers are unchanged.
    const isForm = typeof FormData !== "undefined" && init?.body instanceof FormData
    const headers: Record<string, string> = isForm ? {} : { "Content-Type": "application/json" }
    Object.assign(headers, (init?.headers as Record<string, string>) ?? {})
    const base = currentBase
    const token = await ensureToken(base)
    if (token) headers["Authorization"] = `Bearer ${token}`
    let response = await fetch(`${base}${path}`, { ...init, signal: controller.signal, headers })
    if (response.status === 401 && token) {
      // Token rejected (e.g. the engine's secret rotated): drop it everywhere
      // and re-register once.
      delete tokenByBase[base]
      try {
        await SecureStore.deleteItemAsync(TOKEN_KEY)
        await SecureStore.deleteItemAsync(TOKEN_BASE_KEY)
      } catch {
        // ignore; in-memory delete above is enough to force re-registration
      }
      const fresh = await ensureToken(base)
      if (fresh) {
        headers["Authorization"] = `Bearer ${fresh}`
        response = await fetch(`${base}${path}`, { ...init, signal: controller.signal, headers })
      }
    }
    if (!response.ok) {
      const body = await response.text()
      throw new Error(`Engine returned ${response.status}: ${body.slice(0, 200)}`)
    }
    return (await response.json()) as T
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      // Likely a cold start: the hosted engine was asleep. Retry once with a
      // budget long enough for it to wake before we fall back to on-device.
      if (!isRetry) {
        clearTimeout(timer)
        return request<T>(path, init, COLD_START_MS, true)
      }
      throw new Error(
        `The verdict engine did not respond at ${currentBase}. Set the Engine URL in Protection settings, or check it is running.`,
      )
    }
    throw error
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Fire-and-forget wake-up for a sleeping hosted engine. Safe to call on app
 * launch: it pings /health with a cold-start budget and ignores every error,
 * so by the time the user runs a real check the engine is already awake.
 */
export function warmEngine(): void {
  request("/health", undefined, COLD_START_MS, true).catch(() => {})
}

export function check(
  input: string,
  language: "mr" | "hi" = "mr",
): Promise<VerdictResult> {
  return request<VerdictResult>("/check", {
    method: "POST",
    body: JSON.stringify({ input, language, explain: true, record: true }),
  })
}

/**
 * Forensic analysis of a raw .eml [SIH26106]. Returns the standard verdict plus
 * the email_forensics block (auth, origin+geo, domain intel, 5-label). `mask`
 * masks PII in the display; `withCase` also returns the chain-of-custody file.
 */
export function checkEmail(
  raw: string,
  opts?: { language?: "mr" | "hi" | "en"; mask?: boolean; withCase?: boolean },
): Promise<EmailResult> {
  const fd = new FormData()
  fd.append("raw", raw)
  fd.append("language", opts?.language ?? "en")
  if (opts?.mask) fd.append("mask", "true")
  if (opts?.withCase) fd.append("case", "true")
  return request<EmailResult>("/check/email", { method: "POST", body: fd })
}

/**
 * Check a QR payload the phone's camera already decoded.
 *
 * Sends the decoded text to /check/qr as a form field, so the UPI-payee
 * extraction and the whole verdict/evidence flow stay server-side and
 * identical to every other intake path.
 */
export function checkQr(payload: string, language: "mr" | "hi" = "mr"): Promise<VerdictResult> {
  const body = new FormData()
  body.append("text", payload)
  body.append("language", language)
  // No Content-Type header: fetch sets the multipart boundary itself.
  return request<VerdictResult>("/check/qr", { method: "POST", body, headers: {} })
}

export function ledgerEvents(): Promise<{ events: LedgerEvent[] }> {
  return request<{ events: LedgerEvent[] }>("/ledger/events")
}

export function verifyChain(): Promise<ChainStatus> {
  return request<ChainStatus>("/ledger/verify")
}

/** DEMO ONLY (engine started with VERIS_DEMO=1): break the chain to show detection. */
export function demoTamper(): Promise<{ tampered: boolean; seq?: number; detail: string }> {
  return request("/ledger/dev/tamper", { method: "POST" })
}

/** DEMO ONLY: re-seal the chain so it verifies green again (repeatable demo). */
export function demoRebuild(): Promise<{ rebuilt: boolean; count: number }> {
  return request("/ledger/dev/rebuild", { method: "POST" })
}

export function submitReport(complaint: Record<string, unknown>): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>("/ledger/report", {
    method: "POST",
    body: JSON.stringify(complaint),
  })
}

export function health(): Promise<{ status: string; engine_version: string; mode: string }> {
  return request("/health")
}
