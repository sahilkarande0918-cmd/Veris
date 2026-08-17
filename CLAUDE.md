# Veris -- project rules

Verifiable digital-fraud detection + tamper-evident incident reporting.
Smart India Hackathon 2026, theme: AI-Assisted Digital Fraud Detection and
Verifiable Cyber Incident Reporting.

## The rule that governs every feature

**The verdict is always produced by deterministic checks against real data
sources. The LLM never decides the verdict. The LLM only explains the
evidence in plain language.**

Practically, that means:

- A `verdict` field may only be written by the rule engine.
- The LLM receives the structured evidence and returns prose. If a response
  tries to state or change a verdict, discard it and re-prompt.
- Every signal ships its citation: `{source, value, observed_at}`. A signal
  with no real source must never be created.
- Every verdict returns `rules_fired` -- the exact rules that produced it.

Ask of any feature: *"how do you know it's a scam?"* If the answer is "the
model said so", it is not done.

## Legal and policy constraints (non-negotiable)

- Output language is "likely scam / possible non-compliance -- verify".
  Never a definitive public accusation against a named brand.
- Never auto-contact a government officer. The user always decides whether
  to report.
- No `READ_SMS` / `READ_CALL_LOG` in the Play-facing build (Play policy ban).
  SMS-screening demos are sideload-only and must be labelled as such.

## Engineering constraints

- **Offline first.** The full demo must run with the network off. External
  APIs are enrichment, never a hard dependency. `VERIS_OFFLINE=1` blocks all
  outbound calls.
- **Cache rate-limited APIs** (VirusTotal is ~4 req/min) with a local TTL
  cache. Never call them in a loop.
- Secrets in `.env` only. Every key name belongs in `.env.example`.
- Python 3.11+ for the backend, TypeScript for mobile.
- `packages/shared/verdict.py` and `verdict.ts` are mirrors. Change both
  together, and keep the JSON field names identical (snake_case).
- Look up official docs before coding against an unfamiliar API. Do not
  assume SDK shapes.

## Working agreement

Ponytail is installed at `full` (`.claude/skills/`, ruleset in `AGENTS.md`).
Follow its ladder, and:

1. Restate the task and its acceptance criteria in one line.
2. Build the smallest version that could work.
3. Leave one runnable check behind. No feature is done without a passing check.
4. Self-review against the acceptance criteria and the rule above.
5. `/ponytail-review`, then commit.

Stop at every CHECKPOINT and wait for a go-ahead.
