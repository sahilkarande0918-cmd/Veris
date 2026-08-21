/**
 * Pure text -> checkable-token extraction, split out from ocr.ts so it can be
 * tested in plain Node (ocr.ts pulls in the ML Kit native module, which only
 * loads on a device).
 */

// Same shapes the engine and on-device triage already use.
const URL_RE = /(?:https?:\/\/|www\.)[^\s<>"']+/i
const VPA_RE = /\b[a-z0-9._-]{2,64}@[a-z][a-z0-9]{1,32}\b/i
// Indian mobile, tolerating the usual "98765 43210" 5-5 grouping and a +91/0 prefix.
const PHONE_RE = /(?:\+?91[-\s]?|0)?[6-9]\d{4}[-\s]?\d{5}\b/

/**
 * The single thing worth checking in OCR'd text.
 *
 * Priority mirrors what a scam actually turns on: a link, then a UPI payee,
 * then a phone number. Returns the exact token the engine's classifier
 * expects (a bare URL / VPA / number), not the whole paragraph.
 */
export function firstCandidate(text: string): string | null {
  const url = text.match(URL_RE)?.[0]
  if (url) return url.replace(/[.,)"']+$/, "")
  const vpa = text.match(VPA_RE)?.[0]
  if (vpa) return vpa.toLowerCase()
  const phone = text.match(PHONE_RE)?.[0]
  if (phone) return phone.replace(/\D/g, "")
  return null
}
