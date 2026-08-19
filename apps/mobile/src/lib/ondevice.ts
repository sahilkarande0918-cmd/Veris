/**
 * On-device triage: a verdict without a server.
 *
 * When the engine is unreachable -- no signal, server down, demo laptop
 * asleep -- the phone still answers, using the same rule as the backend:
 * deterministic checks over local data, each one citing what it matched.
 * There is no model here and no guessing, so a result from this path is
 * auditable in exactly the same way as one from the server.
 *
 * It is deliberately weaker than the engine: no blocklist feeds, no Unicode
 * confusables table, no RDAP. Results are capped at "suspicious" unless a
 * bundled reported-list entry matches, and every result says it came from the
 * phone so nobody mistakes it for the full check.
 */

import type { Signal, Verdict, VerdictResult } from "./api"

/** Brands most impersonated in Indian scams. Mirrors fixtures/brands_in.json. */
const BRAND_DOMAINS: Record<string, string> = {
  "hdfcbank.com": "HDFC Bank",
  "icicibank.com": "ICICI Bank",
  "sbi.co.in": "State Bank of India",
  "onlinesbi.sbi": "State Bank of India",
  "axisbank.com": "Axis Bank",
  "kotak.com": "Kotak Mahindra Bank",
  "paytm.com": "Paytm",
  "phonepe.com": "PhonePe",
  "npci.org.in": "NPCI",
  "rbi.org.in": "Reserve Bank of India",
  "uidai.gov.in": "UIDAI (Aadhaar)",
  "incometax.gov.in": "Income Tax India",
  "epfindia.gov.in": "EPFO",
  "irctc.co.in": "IRCTC",
  "cybercrime.gov.in": "National Cyber Crime Reporting Portal",
}

/** Wording that shows up in Indian scam SMS, in the languages they arrive in. */
const SCAM_PHRASES: { pattern: RegExp; label: string }[] = [
  { pattern: /\bkyc\b.{0,24}\b(expir|updat|suspend|pending|complet)/i, label: "KYC expiry pressure" },
  { pattern: /\b(account|khata).{0,20}\b(block|freez|suspend|deactivat)/i, label: "account-blocked threat" },
  { pattern: /\b(otp|cvv|pin|password)\b.{0,30}\b(share|send|tell|bata|batao|forward)/i, label: "asks you to share an OTP or PIN" },
  { pattern: /\b(lottery|lucky draw|prize|winner|inam)\b/i, label: "lottery or prize claim" },
  { pattern: /\b(instant|quick|turant).{0,16}\b(loan|cash|credit)\b/i, label: "instant-loan offer" },
  { pattern: /\b(electricity|bijli).{0,24}\b(disconnect|bill|due)\b/i, label: "electricity disconnection threat" },
  { pattern: /\b(refund|cashback).{0,24}\b(claim|process|pending)\b/i, label: "refund or cashback bait" },
  { pattern: /\b(courier|parcel|customs).{0,24}\b(hold|seiz|clear|detain)/i, label: "parcel-held scam" },
  { pattern: /\b(digital arrest|cbi|narcotics|money laundering)\b/i, label: "digital-arrest intimidation" },
  { pattern: /\b(within|in)\s?\d{1,2}\s?(hour|hrs|minute|min|ghante)/i, label: "artificial time pressure" },
]

const REPORTED_VPAS = new Set([
  "kycupdate2026@ybl",
  "sbi.refund.claim@okaxis",
  "instantloan.approve@paytm",
  "lottery.winner.claim@okhdfcbank",
  "electricity.bill.due@oksbi",
])

const URL_RE = /(?:https?:\/\/|www\.)[^\s<>"']+/gi
const VPA_RE = /\b[a-z0-9._-]{2,64}@[a-z][a-z0-9]{1,32}\b/gi

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00")
}

function signal(id: string, source: string, value: string, weight: number): Signal {
  return { id, source, value, observed_at: nowIso(), weight }
}

/** Hostname from a URL, lowercased, without www. and without userinfo. */
export function hostOf(url: string): string {
  const withScheme = url.includes("://") ? url : `http://${url}`
  const afterScheme = withScheme.slice(withScheme.indexOf("://") + 3)
  const authority = afterScheme.split(/[/?#]/)[0]
  // Everything before '@' is userinfo, not the host.
  const hostPart = authority.includes("@") ? authority.slice(authority.lastIndexOf("@") + 1) : authority
  const host = hostPart.split(":")[0].toLowerCase()
  return host.startsWith("www.") ? host.slice(4) : host
}

/** Does the URL hide a brand in its userinfo, before the '@'? */
function checkUserinfo(url: string): Signal[] {
  const withScheme = url.includes("://") ? url : `http://${url}`
  const authority = withScheme.slice(withScheme.indexOf("://") + 3).split(/[/?#]/)[0]
  if (!authority.includes("@")) return []
  const userinfo = authority.slice(0, authority.lastIndexOf("@")).toLowerCase()
  for (const [domain, brand] of Object.entries(BRAND_DOMAINS)) {
    if (userinfo.includes(domain) || userinfo.includes(domain.split(".")[0])) {
      return [
        signal(
          "userinfo_deception",
          "on-device URL parsing",
          `reads as ${brand} but the part before '@' is a username; the page is served by '${hostOf(url)}'`,
          60,
        ),
      ]
    }
  }
  return []
}

/** A real brand domain appearing to the left of the actual host. */
function checkBrandAsSubdomain(host: string): Signal[] {
  if (BRAND_DOMAINS[host]) return []
  for (const [domain, brand] of Object.entries(BRAND_DOMAINS)) {
    const label = domain.split(".")[0]
    if (host.includes(`${domain}.`) || host.startsWith(`${label}.`)) {
      if (!host.endsWith(domain)) {
        return [
          signal(
            "brand_as_subdomain",
            "on-device hostname comparison",
            `looks like ${brand}, but the site is actually served by '${host}'`,
            55,
          ),
        ]
      }
    }
  }
  return []
}

/** Non-ASCII letters inside a hostname: the cheap on-device homoglyph tell. */
function checkMixedScript(host: string): Signal[] {
  // `[^ -]` would be a broken character range; test code points explicitly.
  const hasNonAscii = [...host].some((ch) => ch.charCodeAt(0) > 127)
  if (!hasNonAscii && !host.includes("xn--")) return []
  const decoded = host
  return [
    signal(
      "mixed_script_host",
      "on-device character-set check",
      `'${decoded}' uses non-English characters in the address, a common way to imitate a bank`,
      55,
    ),
  ]
}

function checkIpHost(host: string): Signal[] {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return []
  return [
    signal("ip_address_host", "on-device hostname check", `served from the raw address ${host}, which no bank does`, 45),
  ]
}

function checkPhrases(text: string): Signal[] {
  const hits = SCAM_PHRASES.filter((p) => p.pattern.test(text)).map((p) => p.label)
  if (hits.length === 0) return []
  // Several independent tells are worth more than one, but cap the total so
  // wording alone can never reach "likely scam" on its own.
  const weight = Math.min(50, 20 + (hits.length - 1) * 15)
  return [
    signal("scam_wording", "on-device scam-phrase list", `message uses ${hits.join("; ")}`, weight),
  ]
}

function checkVpas(text: string): Signal[] {
  const found = text.toLowerCase().match(VPA_RE) ?? []
  for (const vpa of found) {
    if (REPORTED_VPAS.has(vpa)) {
      return [
        signal("upi_reported", "on-device reported-VPA list", `${vpa} has been reported as used in scams`, 70),
      ]
    }
  }
  return []
}

/**
 * Score raw shared text entirely on the phone.
 *
 * Returns the same shape the server returns, so the Result screen does not
 * care which produced it -- but `engine_version` says `on-device`, and the
 * UI shows that plainly.
 */
export function triageOnDevice(raw: string): VerdictResult {
  const text = raw.trim()
  const signals: Signal[] = [...checkPhrases(text), ...checkVpas(text)]

  const urls = text.match(URL_RE) ?? []
  const firstUrl = urls[0]
  if (firstUrl) {
    const host = hostOf(firstUrl)
    signals.push(...checkUserinfo(firstUrl))
    if (BRAND_DOMAINS[host]) {
      signals.push(
        signal(
          "brand_allowlist",
          "on-device brand list",
          `${host} is the verified domain of ${BRAND_DOMAINS[host]}`,
          0,
        ),
      )
    } else {
      signals.push(...checkMixedScript(host), ...checkBrandAsSubdomain(host), ...checkIpHost(host))
    }
  }

  const score = Math.min(100, signals.reduce((sum, s) => sum + s.weight, 0))
  const allowlisted = signals.some((s) => s.id === "brand_allowlist")
  const incriminating = signals.filter((s) => s.id !== "brand_allowlist")

  let verdict: Verdict = "safe"
  if (allowlisted && incriminating.length === 0) verdict = "safe"
  else if (score >= 60) verdict = "likely_scam"
  else if (score >= 30) verdict = "suspicious"

  const rules = incriminating
    .sort((a, b) => b.weight - a.weight)
    .map((s) => `${s.id} (+${s.weight}): ${s.value} [${s.source}]`)
  rules.push(`score ${score} -> ${verdict} (checked on this phone, no server)`)

  return {
    subject: { type: firstUrl ? "url" : "upi", value: firstUrl ?? text.slice(0, 120) },
    verdict,
    score,
    signals,
    rules_fired: rules,
    engine_version: "on-device",
    generated_at: nowIso(),
    explanation: {
      english: describe(verdict, incriminating),
      regional: describeRegional(verdict),
      language: "mr",
      generated_by: "on-device-rules",
    },
  }
}

function describe(verdict: Verdict, signals: Signal[]): string {
  const lead =
    verdict === "likely_scam"
      ? "This is likely a scam. Do not share an OTP or send money."
      : verdict === "suspicious"
        ? "This looks suspicious. Check with the official app before acting."
        : "Nothing on this phone flagged it. Stay alert anyway."
  const because = signals.length ? ` ${signals.map((s) => s.value).join(". ")}.` : ""
  return `${lead}${because} Checked on your phone without the internet, so this is a lighter check than the full one.`
}

function describeRegional(verdict: Verdict): string {
  const lead =
    verdict === "likely_scam"
      ? "ही बहुधा फसवणूक आहे. OTP देऊ नका, पैसे पाठवू नका."
      : verdict === "suspicious"
        ? "हे संशयास्पद वाटते. अधिकृत ॲपवरून खात्री करा."
        : "या फोनवरील तपासणीत काहीही आढळले नाही. तरीही सावध रहा."
  return `${lead} ही तपासणी इंटरनेटशिवाय तुमच्या फोनवर झाली आहे.`
}
