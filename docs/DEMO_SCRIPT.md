# Veris — 90-second demo script

Rehearse this. The whole thing runs with the network off.

## Before you walk up

```bash
cd services/verdict-engine && .venv/Scripts/python -m uvicorn app.main:app --port 8000
```

```bash
adb reverse tcp:8000 tcp:8000 && curl -s http://127.0.0.1:8000/health
```

Checklist:

- [ ] `/health` returns `{"status":"ok"}`
- [ ] `python scripts/demo_all.py` exits 0
- [ ] phone unlocked, screen timeout set to 10 minutes, Veris already open
- [ ] terminal font large enough to read from the back of the room
- [ ] **aeroplane mode ON** — the point is that it still works
- [ ] fallback video queued (see below)

---

## The script

### 0:00 — The problem (10s)

> "Every scam detector says *this is a scam, 87% confidence*. Ask it **how it
> knows** and there's no answer, because a language model guessed. Veris never
> guesses."

### 0:10 — Catch what others miss (20s)

Share this into Veris from any app, or paste it:

```
https://xn--icicibnk-66g.com/login
```

> "That's `icicibank.com` with one Cyrillic character. It's on no blocklist.
> A substring check sees nothing wrong."

Point at the red badge.

> "Veris says **likely scam** — and here's the receipt."

### 0:30 — The evidence panel (20s)

Scroll to the evidence panel. Read one line aloud:

> "`homoglyph_impersonation`, source: **Unicode UTS #39 confusables skeleton**,
> observed at 10:42. Not an opinion — a named source with a timestamp. The
> verdict is these signals added up. The model never touches it."

Tap the **मराठी** toggle.

> "The model's only job is this: explaining the evidence in the victim's own
> language. It cannot change the verdict — the type it returns has no verdict
> field."

### 0:50 — The tamper-evident log (25s)

```bash
python scripts/demo_ledger.py
```

> "Every check is appended to a hash-chained log. Watch me forge it."

Point at step 5:

> "I changed a verdict from *likely scam* to *safe*. Caught, record #2."

Point at step 6 — **this is the moment**:

> "Now I'm the smarter attacker: I recompute that record's own hash so it's
> self-consistent. The break just moves to record #3, because #3 still points
> at the original. To hide one edit I'd have to rewrite every record after it
> — and the chain head is signed."

If asked *why not blockchain*:

> "Blockchain solves consensus between distrusting parties. This is one
> evidence log. A hash chain solves it completely — with no network, which is
> why it works on a phone in a village with no signal."

### 1:15 — The packet (15s)

Tap **Create evidence packet**.

> "NCRP's own fields — amount, UPI id, UTR — plus every signal with its source
> and the chain status, so whoever receives it can verify nothing was edited.
> We file nothing. There's no public NCRP API, and the decision to report is
> the victim's."

### 1:30 — Close (5s)

> "Deterministic verdicts, cited evidence, tamper-evident reporting. Works
> offline. Ask me how it knows — there's always an answer."

---

## If they ask for more

| Question | Run this |
|---|---|
| "Is it better than a simple checker?" | `python scripts/demo_adversarial.py` → naive 5/9, Veris 9/9 |
| "What about fake loan apps?" | `python scripts/demo_apk.py` → contacts+SMS = the extortion kit |
| "Does it work offline?" | `python scripts/demo_all.py` → all checks, aeroplane mode |
| "What permissions do you need?" | `INTERNET` only. Proven on the release manifest. |

## Answers to the hard questions

**"Your blocklists are fake."** Correct — they're synthetic demo data, labelled
as such in `fixtures/README.md`, because we won't ship a file naming real
domains as scams. `scripts/refresh_blocklists.py` pulls the live feeds.

**"Your RBI list is incomplete."** Also correct, and it's why a miss is scored
*suspicious* with "verify on the RBI directory", never "illegitimate".

**"Can you prove *when* something happened?"** No, and we say so in the packet.
The chain proves order and integrity; wall-clock time is asserted by the
device. RFC 3161 anchoring is the upgrade path and is not implemented — we'd
rather ship no timestamp than a fake one.

**"What if the LLM is down?"** It falls back to a deterministic template, in
Marathi and Hindi. That's what you just watched — the demo ran offline.

## Fallback video

Record `python scripts/demo_all.py` plus the phone flow **before demo day**,
in case the venue laptop misbehaves. Keep it on the presenting machine, not in
the cloud.
