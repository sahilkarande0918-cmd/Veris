/**
 * Veris shared schema: verdicts and evidence.
 *
 * Mirror of `verdict.py` (the backend source of truth) -- change both together.
 *
 * Design rule (see CLAUDE.md): a Verdict comes ONLY from deterministic rules
 * over Signals. An Explanation is LLM prose and never alters the verdict.
 */

export type Verdict = "safe" | "suspicious" | "likely_scam"

export type SubjectType = "url" | "domain" | "phone" | "upi" | "apk_hash"

/** One piece of evidence from one named source. */
export interface Signal {
  /** Stable machine id, e.g. "domain_age". */
  id: string
  /** Human-readable origin shown in the evidence panel, e.g. "RDAP (registry)". */
  source: string
  /** What was observed, e.g. "registered 4 days ago". */
  value: string
  /** ISO-8601 UTC. */
  observed_at: string
  /** Points this signal contributes to the score. */
  weight: number
}

/** What was checked. */
export interface Subject {
  type: SubjectType
  value: string
}

/** LLM prose. Contains no verdict of its own. */
export interface Explanation {
  english: string
  regional: string
  /** e.g. "mr", "hi" */
  language: string
  /** e.g. "groq:llama-3.3-70b" or "template-fallback" */
  generated_by: string
}

/** The full, citable answer returned to the app. */
export interface VerdictResult {
  subject: Subject
  verdict: Verdict
  /** 0-100, higher = more suspicious. */
  score: number
  signals: Signal[]
  /** Exact rule names that produced the verdict. */
  rules_fired: string[]
  engine_version: string
  generated_at: string
  explanation?: Explanation | null
}
