# Veris

Verifiable digital-fraud detection and tamper-evident cyber-incident reporting.
Built for Smart India Hackathon 2026.

Veris answers one question that most scam detectors dodge: **how do you know?**
Every verdict is produced by deterministic checks against named data sources,
and every signal is returned with its citation. A language model is used only
to explain that evidence in plain English and a regional language -- it never
decides, and never changes, the verdict.

## Status

| Phase | What | State |
|---|---|---|
| 0 | Monorepo, shared schema, health route | done |
| 1 | Verdict engine: deterministic checks | done |
| 2 | Explanation layer (Groq, explains only) | todo |
| 3 | Tamper-evident evidence ledger | todo |
| 4 | Android app (share-sheet intake, evidence panel) | todo |
| 5 | Point-of-attack features (APK, call screening) | todo |
| 6 | India grounding + adversarial demo | todo |
| 7 | Demo hardening | todo |

## Layout

```
services/verdict-engine/   Python FastAPI -- the deterministic brain
packages/shared/           verdict schema, mirrored for Python and TypeScript
fixtures/                  seed scams + safe samples, so the demo runs offline
apps/mobile/               Expo React Native app (Phase 4)
tooling/                   ponytail checkout (agent discipline, not a dependency)
```

## Run the verdict engine

Requires Python 3.11+ (tested on 3.13).

```bash
cd services/verdict-engine && python -m venv .venv
```

Then install and start. On Windows (Git Bash / PowerShell):

```bash
services/verdict-engine/.venv/Scripts/python -m pip install -r services/verdict-engine/requirements.txt
```

```bash
cd services/verdict-engine && .venv/Scripts/python -m uvicorn app.main:app --reload --port 8000
```

On macOS or Linux use `.venv/bin/python` in place of `.venv/Scripts/python`.

Check it:

```bash
curl http://127.0.0.1:8000/health
```

```json
{ "status": "ok", "engine_version": "0.1.0" }
```

Interactive API docs are at http://127.0.0.1:8000/docs.

## Check something

`POST /check` takes raw text -- a whole SMS, a bare domain, a UPI id, a phone
number, an APK hash -- works out what it is, and returns the evidence.

```bash
curl -X POST http://127.0.0.1:8000/check -H "Content-Type: application/json" -d '{"input":"https://xn--icicibnk-66g.com/login"}'
```

That input is a Cyrillic-`а` lookalike of `icicibank.com`. A substring check
sees nothing wrong with it. Veris returns:

```json
{
  "verdict": "likely_scam",
  "score": 65,
  "signals": [
    {
      "id": "homoglyph_impersonation",
      "source": "Unicode UTS #39 confusables skeleton",
      "value": "'icicibаnk.com' renders as 'icicibank.com' (ICICI Bank) using lookalike characters",
      "observed_at": "2026-08-18T...+00:00",
      "weight": 65
    }
  ],
  "rules_fired": ["homoglyph_impersonation (+65): ...", "score 65 -> likely_scam (likely_scam >= 60, suspicious >= 30)"]
}
```

Note what is *not* in that response: an opinion. The verdict is the arithmetic
of the signal weights, and every signal names the source it came from.

### What it checks, offline

| Check | Source | Weight |
|---|---|---|
| Blocklist hit | PhishTank / URLhaus / OpenPhish local snapshots | 70 |
| Homoglyph impersonation | Unicode UTS #39 confusable skeleton | 65 |
| Brand as subdomain | Public Suffix List registrable-domain comparison | 55 |
| Typosquat | Levenshtein <= 2 vs curated Indian brand list | 45 |
| Reported UPI VPA | local reported list | 70 |
| Malformed UPI VPA | NPCI VPA format rules | 30 |
| Verified brand domain | curated Indian brand list | allowlist |

Scores are summed and capped at 100: `>= 60` is `likely_scam`, `>= 30` is
`suspicious`, below that `safe`.

### What it adds when online

Safe Browsing v4, VirusTotal v3 (cached 24h for the ~4 req/min free tier),
RDAP registration date, and the live TLS certificate. All four are
**enrichment**: if a key is missing or the network is down they contribute
nothing and the verdict still returns. `VERIS_OFFLINE=1` disables them
outright.

## Run the tests

```bash
cd services/verdict-engine && .venv/Scripts/python -m pytest -q
```

## Configuration

Copy `.env.example` to `.env` and fill in what you have. **Every key is
optional.** With no keys at all the engine still returns a verdict from local
blocklists and offline checks -- that is deliberate, so a live demo never
depends on a network call. Set `VERIS_OFFLINE=1` to block outbound calls
entirely.

## Attribution

URL reputation enrichment uses Google Safe Browsing ("Advisory provided by
Google") and VirusTotal. Blocklist data comes from PhishTank, URLhaus
(abuse.ch), and OpenPhish.

## Notes for contributors

Read [CLAUDE.md](CLAUDE.md) first -- it holds the one rule that shapes the
whole design, plus the legal and Play-policy constraints.
