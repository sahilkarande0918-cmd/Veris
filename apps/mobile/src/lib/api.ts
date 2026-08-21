/**
 * Client for the Veris verdict engine.
 *
 * The types below mirror `packages/shared/verdict.ts`, which is the source of
 * truth. Metro cannot resolve modules outside the app directory without
 * monorepo config, so they are duplicated deliberately -- if you change the
 * schema, change both.
 */

export type Verdict = "safe" | "suspicious" | "likely_scam"
export type SubjectType = "url" | "domain" | "phone" | "upi" | "apk_hash"

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

import AsyncStorage from "@react-native-async-storage/async-storage"

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
    const saved = await AsyncStorage.getItem(ENGINE_URL_KEY)
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
    if (cleaned) await AsyncStorage.setItem(ENGINE_URL_KEY, cleaned)
    else await AsyncStorage.removeItem(ENGINE_URL_KEY)
  } catch {
    // best effort; the in-memory value still applies for this session
  }
}

const TIMEOUT_MS = 20000

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    // FormData sets its own multipart Content-Type (with a boundary); forcing
    // JSON would corrupt the upload. JSON callers are unchanged.
    const isForm = typeof FormData !== "undefined" && init?.body instanceof FormData
    const headers: Record<string, string> = isForm ? {} : { "Content-Type": "application/json" }
    Object.assign(headers, (init?.headers as Record<string, string>) ?? {})
    const response = await fetch(`${currentBase}${path}`, {
      ...init,
      signal: controller.signal,
      headers,
    })
    if (!response.ok) {
      const body = await response.text()
      throw new Error(`Engine returned ${response.status}: ${body.slice(0, 200)}`)
    }
    return (await response.json()) as T
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(
        `The verdict engine did not respond at ${currentBase}. Set the Engine URL in Protection settings, or check it is running.`,
      )
    }
    throw error
  } finally {
    clearTimeout(timer)
  }
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
