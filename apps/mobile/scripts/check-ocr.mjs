/**
 * Runnable check for the OCR text -> checkable-token extraction.
 *
 *   node --experimental-strip-types scripts/check-ocr.mjs
 *
 * ML Kit itself only runs on the device, so this tests the pure part: given
 * the text ML Kit would return from a scam screenshot, do we pull out the
 * right thing to check? That is the logic that can silently break.
 */

import assert from "node:assert/strict"

const { firstCandidate } = await import("../src/lib/ocr-extract.ts")

let n = 0
const check = (name, fn) => {
  fn()
  n++
  console.log(`  ok  ${name}`)
}

check("pulls the link out of a fake-payment SMS screenshot", () => {
  const ocr = "URGENT your SBI KYC expired. Update at https://xn--icicibnk-66g.com/login within 2 hours"
  assert.equal(firstCandidate(ocr), "https://xn--icicibnk-66g.com/login")
})

check("pulls the UPI id when there is no link", () => {
  const ocr = "Pay Rs 4999 refund to kycupdate2026@ybl now to release your parcel"
  assert.equal(firstCandidate(ocr), "kycupdate2026@ybl")
})

check("prefers a link over a UPI id when both are present", () => {
  const ocr = "click http://sbi-kyc.top/x or pay kycupdate2026@ybl"
  assert.equal(firstCandidate(ocr), "http://sbi-kyc.top/x")
})

check("pulls an Indian phone number in every common written form", () => {
  // +91 with/without space/hyphen, 5-5 grouping, bare 10-digit, 0-prefix, embedded.
  assert.equal(firstCandidate("Call +919876543210 now"), "919876543210")
  assert.equal(firstCandidate("Call +91 9876543210 now"), "919876543210")
  assert.equal(firstCandidate("Call +91-9876543210 now"), "919876543210")
  assert.equal(firstCandidate("Call back on +91 98765 43210"), "919876543210")
  assert.equal(firstCandidate("dial 9876543210"), "9876543210")
  assert.equal(firstCandidate("ring 9123456789 today"), "9123456789")
})

check("strips trailing punctuation from a link", () => {
  assert.equal(firstCandidate("verify at http://sbi-kyc.top/x."), "http://sbi-kyc.top/x")
})

check("returns null when the screenshot has nothing checkable", () => {
  assert.equal(firstCandidate("Happy birthday! See you at the party tonight."), null)
})

console.log(`\n${n} OCR extraction checks passed.`)
