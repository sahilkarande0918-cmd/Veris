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

/**
 * Over USB, run `adb reverse tcp:8000 tcp:8000` so the phone's localhost
 * reaches the engine on your machine. Override with EXPO_PUBLIC_VERIS_API
 * (e.g. your LAN IP) when running over Wi-Fi instead.
 */
export const API_BASE = process.env.EXPO_PUBLIC_VERIS_API ?? "http://127.0.0.1:8000"

const TIMEOUT_MS = 20000

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    })
    if (!response.ok) {
      const body = await response.text()
      throw new Error(`Engine returned ${response.status}: ${body.slice(0, 200)}`)
    }
    return (await response.json()) as T
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(
        `The verdict engine did not respond at ${API_BASE}. Is it running, and did you run 'adb reverse tcp:8000 tcp:8000'?`,
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

export function ledgerEvents(): Promise<{ events: LedgerEvent[] }> {
  return request<{ events: LedgerEvent[] }>("/ledger/events")
}

export function verifyChain(): Promise<ChainStatus> {
  return request<ChainStatus>("/ledger/verify")
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
