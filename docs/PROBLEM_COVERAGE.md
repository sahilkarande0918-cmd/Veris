# Veris vs the problem statement, line by line

An honest map of what the theme asks for and where Veris delivers it. "Partial"
and "roadmap" are marked as such on purpose — a judge trusts a team that knows
its own gaps.

## 1. Real Problem

| Threat | Status | Where |
|---|---|---|
| Phishing | done | blocklists, homoglyph, brand-as-subdomain, userinfo trick |
| Malicious links | done | full URL engine + live enrichment |
| Fake payment requests | done | UPI VPA validation + reported-VPA list |
| **QR-code scams** | **done** | `/check/qr` decodes the QR and judges the UPI payee / link inside |
| Impersonation | done | Unicode UTS #39 lookalike detection |
| Fraudulent messages | done | notification guard + scam-wording checks, EN/HI/MR |

## 2. Measurable Inputs

| Input | Status | Where |
|---|---|---|
| SMS | done | notification guard (no READ_SMS) + share sheet |
| Email | done | notification guard reads email notifications |
| URL | done | `/check` |
| **QR code** | **done** | `/check/qr` |
| Website information | done | RDAP age, live TLS cert, VirusTotal |
| Message text | done | `/check` + on-device triage |
| Screenshot | partial | hashed into the evidence packet; OCR of screenshot text is roadmap |
| Incident report | done | tamper-evident ledger + NCRP packet |

## 3. Intelligent Processing

| Capability | Status | Where |
|---|---|---|
| Classify threat | done | deterministic verdict (safe / suspicious / likely_scam) |
| Calculate risk score | done | 0–100, transparent weighted sum |
| Identify suspicious patterns | done | each signal names the pattern it matched |
| Explain why | done | LLM writes prose from the evidence, in EN + HI/MR, never decides |
| Correlate reported incidents | partial | ledger stores incidents; `/intel/rules` aggregates reported ids into the national feed. A per-incident correlation view is roadmap. |

## 4. Physical / Digital Action

| Action | Status | Where |
|---|---|---|
| Warn user | done | notification-bar warning within ~1s, no interaction needed |
| Block/flag where possible | done | call screening rejects reported numbers; messages are warned-not-blocked by design (we never alter a user's messages) |
| Generate incident report | done | NCRP/1930-aligned complaint packet |
| Store verifiable evidence | done | SHA-256 hash-chained ledger, tamper-detectable |
| Notify security administrators | partial | deep-links to cybercrime.gov.in / 1930 / Chakshu; a direct SOC/admin channel is roadmap (needs a recipient system) |

## 5. Measurable Outcome

Run `python scripts/benchmark.py`. On the labelled fixture set, offline:

| Metric | Result |
|---|---|
| Detection accuracy | 100% (23/23) |
| False-positive rate | 0% (0/10 good) |
| False-negative rate | 0% (0/13 bad) |
| Threats caught | 13/13 |
| Detection time (median) | 0.08 ms |
| Detection time (p95) | ~1 ms |
| Incident-report integrity | `GET /ledger/verify` proves the chain, live |
| User response rate | roadmap — needs deployment telemetry |

These are sanity-check/demo numbers on a small curated set, not a peer-reviewed
benchmark — the script says so itself. What they prove is the thing that
matters for a citizen tool: **deterministic, millisecond, 0% false positives on
known-good Indian brand and government domains.**

## Technology tags

- **AI/ML, NLP** — the explanation layer (Groq LLM) and the scam-wording NLP
  patterns. The LLM explains; it never decides the verdict.
- **Cybersecurity** — the whole deterministic engine, homoglyph/UTS #39,
  APK static analysis, call/notification screening.
- **Blockchain** — a **hash chain**, not a blockchain, and we argue why that is
  the correct choice for a single tamper-evident evidence log (no consensus
  problem to solve; see README "Why a hash chain and not a blockchain"). If a
  judge insists on the literal word, the chain-head signing + optional RFC 3161
  anchoring is the honest upgrade path.

## The honest gaps, in one place

- **Screenshot OCR** — we hash screenshots as evidence but do not yet read text
  out of them. Real work (an OCR dependency); roadmap.
- **Per-incident correlation** — incidents are stored and aggregated to the
  national feed; a correlation UI is roadmap.
- **Direct admin/SOC notification** — we deep-link to the government rails; a
  push channel to a named administrator needs a recipient system.
- **User-response-rate metric** — needs real deployment telemetry.
