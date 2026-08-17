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
| 1 | Verdict engine: deterministic checks | next |
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
