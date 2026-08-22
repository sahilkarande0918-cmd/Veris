# Veris Backend — Penetration Test Report

**Date:** 2026-08-22
**Target:** Veris FastAPI verdict engine, local instance `http://127.0.0.1:8010`
(reached from the sandbox as `http://host.docker.internal:8010`)
**Test config:** auth ON (`VERIS_AUTH_SECRET` set), `VERIS_OFFLINE=0` (network
enrichment live so the SSRF surface is reachable), `VERIS_DEMO=0`, no real
third-party API keys (Safe Browsing / VirusTotal disabled), isolated ledger.

## Tooling note — Strix could not execute here

Strix (`strix-agent` 1.5.3) was installed and fully set up: Docker daemon up,
sandbox image `ghcr.io/usestrix/strix-sandbox:1.3.0` pulled, target reachable
from the sandbox. The scan **could not run** because no compatible, funded LLM
key was available:

- **Anthropic** (`anthropic/claude-sonnet-4-6`): key had **no credits**
  (`credit balance is too low`).
- **Groq** (`groq/openai/gpt-oss-120b`): **incompatible** — Groq's function-call
  validator rejects Strix's tool schemas
  (`invalid JSON schema for tool view_agent_graph … 'required' present but
  'properties' is missing`).

Strix's recommended providers are OpenAI/Anthropic/Gemini with credits. To run
the real Strix pass, provide a funded key for one of those and re-run:
`STRIX_LLM=<provider/model> LLM_API_KEY=<key> strix -n -t http://host.docker.internal:8010 -t veris_openapi.json --instruction-file strix_instruction.md -m quick --max-budget 2`

**In its place**, a manual pentest of the exact requested scope was performed
against the running backend, with reproducible PoCs. Findings below are from
that manual pass, not Strix.

## Findings

### F1 — SSRF via URL/domain enrichment · Severity: MEDIUM · CONFIRMED

The engine enriches a `url`/`domain` subject by connecting to its host:
`app/enrich.py` `tls_certificate()` opens a raw TLS socket to
`(host, 443)`, and `domain_age()` does `httpx.get("https://rdap.org/domain/{domain}", follow_redirects=True)`.
The `host`/`domain` come straight from attacker-supplied `input`, so an attacker
makes the backend initiate outbound connections to addresses of their choosing.

**PoC** (response latency = the backend dialing the chosen host, `_TIMEOUT=6s`):

| input | response time |
|---|---|
| `example-nonexistent-zzz.test` (control) | 0.55 s |
| `https://127.0.0.1/` | 2.37 s |
| `https://192.0.2.1/` (non-routable) | **6.55 s** (full connect timeout) |

The 6.5 s stall on a non-routable address proves the server attempted an
outbound TCP connection to the attacker-specified host. This is a **blind** SSRF
(connect-only, port 443, no response body reflected to the attacker), usable as
an internal connectivity/port oracle via timing and to poke internal :443
services.

**Proposed fix:** an SSRF guard in `enrich.py` — resolve the host and refuse
private/loopback/link-local/reserved ranges (`ipaddress` stdlib) before
connecting; return `[]` (the existing graceful-degradation path). **Touches:**
enrichment only. Does NOT touch verdict logic (enrichment already returns `[]`
on failure), the ledger, or the demo.

### F2 — Rate-limit bypass via unlimited token minting · Severity: MEDIUM · CONFIRMED

Rate limits (Tier 2 #7) are keyed by device id, and `/auth/device` is in the
open/un-rate-limited set. An attacker mints unlimited device tokens, each with a
fresh per-endpoint budget, defeating the quota protection the limiter exists for.

**PoC:**
- 150/150 rapid `POST /auth/device` calls succeeded (no throttle).
- A token burned to `429` on `/check`; a **freshly minted** token immediately
  got `200` on `/check` — new token = new budget.

**Proposed fix:** rate-limit `/auth/device` by client IP, and add an IP-keyed
limit layer alongside the device-keyed one, in `app/security.py` +
the middleware in `app/main.py`. **Touches:** auth/rate-limit only. Does NOT
touch verdict logic, the ledger, or the demo.

### F3 — Evidence ledger not access-scoped · Severity: MEDIUM (deployment-dependent) · CONFIRMED

`GET /ledger/events` returns the **entire** shared ledger to **any** registered
device, including `/ledger/report` complaint packets that can contain victim PII.

**PoC:** a device (`unrelated-dev-99`) with its own token read all ledger events
it never created.

This is inherent to the design: the ledger is a single tamper-evident chain per
engine instance, intended for a **single-tenant / self-hosted** deployment. On a
**shared/multi-user hosted** engine it is cross-tenant disclosure.

**Recommended handling:** accept + document as single-tenant (deploy one engine
per user / do not multi-tenant the hosted engine). A true fix (per-device
ledgers) would change the ledger model and `/ledger/verify` semantics and the
History-screen demo — **out of scope** for this hardening pass and flagged as
such, per the rule not to alter the ledger or demo.

## Validated NON-findings (tested, not exploitable)

- **Injection (SQL/NoSQL/command/SSTI):** payloads `{{7*7}}`, `$(id)`,
  `; ls -la`, `' OR '1'='1` on `input` all returned `422` (rejected by the typed
  classifier). The app has no SQL/DB and no shell calls; the ledger is JSONL.
- **Mass assignment:** posting extra `verdict`/`score`/`signals`/`rules_fired`
  to `/check` did **not** change the result — server still computed
  `verdict=likely_scam, score=65`. The deterministic verdict cannot be overridden
  by the client (the core Veris rule holds under attack).
- **Insecure file upload:** `/check/apk` and `/check/qr` enforce size caps and
  content-type/extension checks (Tier 1 #3); the APK is written to a
  `TemporaryDirectory` under a fixed name (`upload.apk`), so the client filename
  is never used — no path traversal. Non-image/non-apk uploads → `422`.
- **Auth forgery:** HMAC device tokens; forged/altered tokens → `401`.

## Summary

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| F1 | SSRF via enrichment | Medium | fix proposed (enrich.py guard) |
| F2 | Rate-limit bypass (token minting) | Medium | fix proposed (IP-keyed limit) |
| F3 | Ledger not access-scoped | Medium* | recommend accept+document (single-tenant) |

*F3 severity depends on deployment; single-tenant self-host = low/none.

No fixes have been applied — awaiting per-finding approval.
