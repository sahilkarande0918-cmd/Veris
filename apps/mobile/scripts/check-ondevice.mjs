/**
 * Runnable check for the on-device triage rules.
 *
 *   node --experimental-strip-types scripts/check-ondevice.mjs
 *
 * ponytail: no test framework. Node 24 strips the TypeScript types itself, so
 * this imports the real module rather than a copy that can drift from it.
 */

import assert from "node:assert/strict"

const { triageOnDevice, hostOf } = await import("../src/lib/ondevice.ts")

let checks = 0
function check(name, fn) {
  fn()
  checks++
  console.log(`  ok  ${name}`)
}

check("userinfo trick resolves to the real host", () => {
  assert.equal(hostOf("http://hdfcbank.com@secure-verify.top/login"), "secure-verify.top")
  assert.equal(hostOf("https://WWW.Example.com:8443/x"), "example.com")
})

check("brand hidden before '@' is caught", () => {
  const r = triageOnDevice("http://hdfcbank.com@secure-verify.top/login")
  assert.equal(r.verdict, "likely_scam")
  assert.ok(r.signals.some((s) => s.id === "userinfo_deception"))
})

check("brand as a subdomain of an attacker domain is caught", () => {
  const r = triageOnDevice("https://hdfcbank.com.secure-verify.top/login")
  assert.ok(r.signals.some((s) => s.id === "brand_as_subdomain"))
  assert.notEqual(r.verdict, "safe")
})

check("punycode / non-English host is caught", () => {
  const r = triageOnDevice("https://xn--icicibnk-66g.com/login")
  assert.ok(r.signals.some((s) => s.id === "mixed_script_host"))
})

check("raw IP host is flagged", () => {
  const r = triageOnDevice("http://192.168.1.50/sbi/netbanking")
  assert.ok(r.signals.some((s) => s.id === "ip_address_host"))
})

check("a real scam SMS is flagged on wording plus a reported VPA", () => {
  const r = triageOnDevice(
    "URGENT: your SBI KYC has expired, account will be blocked within 2 hours. Pay to kycupdate2026@ybl",
  )
  assert.equal(r.verdict, "likely_scam")
  assert.ok(r.signals.some((s) => s.id === "upi_reported"))
  assert.ok(r.signals.some((s) => s.id === "scam_wording"))
})

check("wording alone never reaches likely_scam", () => {
  const r = triageOnDevice("Your KYC will expire, account may be blocked, claim your refund within 2 hours")
  assert.notEqual(r.verdict, "likely_scam")
})

check("a genuine bank link is not flagged", () => {
  const r = triageOnDevice("https://www.hdfcbank.com/")
  assert.equal(r.verdict, "safe")
  assert.ok(r.signals.some((s) => s.id === "brand_allowlist"))
})

check("every signal carries a source and a timestamp", () => {
  const r = triageOnDevice("http://hdfcbank.com@secure-verify.top/login")
  for (const s of r.signals) {
    assert.ok(s.source, "signal without a source")
    assert.ok(s.value)
    assert.ok(s.observed_at.endsWith("+00:00"))
  }
})

check("results are labelled as on-device so they cannot be mistaken", () => {
  const r = triageOnDevice("https://xn--icicibnk-66g.com/login")
  assert.equal(r.engine_version, "on-device")
  assert.equal(r.explanation?.generated_by, "on-device-rules")
  assert.ok(r.explanation?.regional.length > 0)
})

console.log(`\n${checks} on-device checks passed.`)
