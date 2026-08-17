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
| 2 | Explanation layer (Groq, explains only) | done |
| 3 | Tamper-evident evidence ledger | done |
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

### The explanation layer

`POST /check` also returns an `explanation` in English and a regional language
(`"language": "mr"` for Marathi, `"hi"` for Hindi). It is written by a
Groq-hosted model that is handed **only** the structured evidence.

The model is fenced in three ways, because an unfenced LLM in a fraud tool is
a liability:

1. **Structural.** The `Explanation` type has no verdict field. Any `verdict`
   key the model returns is dropped.
2. **Contradiction guard.** Prose arguing against the verdict it is meant to
   explain is discarded and re-prompted.
3. **Invented-source guard.** If the text name-drops VirusTotal or RDAP when
   no such signal was gathered, it is discarded.

After two failed attempts -- or with no API key, no network, or
`VERIS_OFFLINE=1` -- it falls back to a deterministic template built from the
same signals. The fallback is not a degraded mode; it is the offline demo
path, and it produces real Marathi and Hindi:

> ही बहुधा फसवणूक आहे. कोणतीही वैयक्तिक माहिती किंवा OTP देऊ नका...
> या पत्त्यात खऱ्या बँकेच्या नावासारखी दिसणारी बनावट अक्षरे वापरली आहेत.

Set `GROQ_MODEL` if your account has different models available. Groq retired
`llama-3.3-70b-versatile` on 2026-08-16; the default is now
`openai/gpt-oss-120b`.

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

## The evidence ledger

Every check is appended to `data/ledger.jsonl` as one line carrying the
SHA-256 hash of the line before it. Edit any byte of any earlier record and
every hash after it stops matching.

See it catch a forgery:

```bash
python scripts/demo_ledger.py
```

It records three incidents, exports a complaint packet, edits a verdict in the
log, and shows the chain naming the broken record:

```
broken at : record #2
reason    : contents were altered: stored hash c3eaa2f665a3a232...
            but the data now hashes to 29f98762e4c63b21...
```

Recompute the tampered record's own hash to cover your tracks and the break
just moves downstream, because record #3 still points at the original:

```
broken at : record #3
reason    : prev_hash does not match the previous record's hash
```

To hide an edit you must rewrite every record after it — and then the signed
chain head no longer matches.

| Endpoint | What |
|---|---|
| `GET /ledger/events` | every recorded event, oldest first |
| `GET /ledger/verify` | walk the chain, report the first break and why |
| `POST /ledger/report` | record complaint details, return an NCRP-aligned packet |

### Why a hash chain and not a blockchain

A blockchain solves distributed consensus among mutually distrusting parties.
That is not this problem. This problem is detecting after-the-fact edits to
one evidence log, which a hash chain solves completely — with no network, no
miners, and no tokens, which is also why it still works on a phone in a
village with no signal.

What a chain alone does not give you is proof of *when*. The chain head is
signed (HMAC-SHA256, `VERIS_LEDGER_KEY`) so a full rewrite needs the key, and
`timestamp_anchoring` in the packet states plainly that wall-clock time is
asserted by the device rather than by a trusted third party. RFC 3161
anchoring is the upgrade path and is **not** implemented — the packet says so
rather than implying a timestamp we do not have.

### The complaint packet

`POST /ledger/report` returns the fields NCRP's financial-fraud flow asks for
(incident time, amount, payment mode, suspect UPI/account/bank, UTR, suspect
URLs and phone, screenshot hashes) alongside the automated findings, the chain
verification status, the data-source attributions, and where to file.

Veris **submits nothing anywhere**. There is no public NCRP API, and filing on
someone's behalf would be wrong even if there were. The packet goes to the
user; the user decides.

If the chain is broken, the packet says so — `chain_verified: false` with the
offending sequence number. A packet that quietly omitted tampering would be
evidence laundering.

## Attribution

URL reputation enrichment uses Google Safe Browsing ("Advisory provided by
Google") and VirusTotal. Blocklist data comes from PhishTank, URLhaus
(abuse.ch), and OpenPhish.

## Notes for contributors

Read [CLAUDE.md](CLAUDE.md) first -- it holds the one rule that shapes the
whole design, plus the legal and Play-policy constraints.
