# How Veris scales to a nation

The winning product gets adopted by government, so "does it scale to 100
million phones?" is a real question, not a slide. Here is the honest answer:
the design scales precisely *because* it has no data moat.

## The insight: rules are data, not a model

Veris's detections are a small signed JSON file (`fixtures/ondevice_rules.json`
— brands, scam-wording patterns, reported UPI ids and numbers, blocked hosts,
weights, thresholds). That single fact is what makes national scale cheap:

- A cloud ML model would need GPUs per request, retraining, and a pipeline that
  harvests citizen messages to stay current. That is expensive, privacy-hostile,
  and degrades in the field (45–50% real-world accuracy — see the competitive
  analysis).
- A **signed rules file** is a few kilobytes. It is pushed to every device, runs
  on-device in microseconds, and gets smarter the instant a new scam id is added
  — with **zero citizen data collected**.

## The three-layer architecture

```
   ┌─────────────────────────────────────────────────────────┐
   │  NATIONAL INTEL LAYER  (owned by I4C / DoT, not by us)   │
   │  - the authoritative rules file: reported UPI ids,       │
   │    numbers, hosts, from 1930 / NCRP / Chakshu feeds      │
   │  - signed once, centrally                                │
   └───────────────▲───────────────────────┬─────────────────┘
        reports up │                        │ signed rules down
   ┌───────────────┴───────────────────────▼─────────────────┐
   │  EDGE ENGINE  (services/verdict-engine, horizontally     │
   │  scalable, stateless)                                    │
   │  - deterministic checks + enrichment + explanation       │
   │  - serves /intel/rules to devices                        │
   │  - accepts tamper-evident reports, forwards to the rail  │
   └───────────────▲───────────────────────┬─────────────────┘
     ledger packet │                        │ rules refresh
   ┌───────────────┴───────────────────────▼─────────────────┐
   │  100M PHONES  (the app)                                  │
   │  - judge on-device, offline, in the user's language      │
   │  - never transmit message content                        │
   │  - refresh the rules file when online; fall back to the  │
   │    bundled copy when not                                 │
   └─────────────────────────────────────────────────────────┘
```

## Why each layer scales

**Phones (the hard part, already solved).** All detection is on-device against a
cached rules file. The load on any server is **zero per message checked** — a
phone in a village with no signal still works. This is the opposite of every
cloud competitor, whose cost grows with every message.

**Edge engine (stateless, therefore trivial to scale).** The verdict engine
holds no per-user state. It is a stateless FastAPI service: put N of them behind
a load balancer and capacity is linear. The only shared state is the rules file
(read-mostly, cacheable at the CDN edge) and the append-only ledger (partitioned
per citizen, never cross-read). Rate-limited external APIs (VirusTotal, Safe
Browsing) are cached with a TTL, so 100M devices cause at most a handful of
upstream calls per domain per day.

**National intel layer (the government already runs it).** I4C already
aggregates reported ids through 1930/NCRP; DoT runs Chakshu. Veris does not
replace that — it consumes it as the rules feed and pours citizen reports back
into it as clean, structured, tamper-evident packets. The government owns the
authoritative data; Veris is the distribution and front-end.

## The network effect, without the privacy cost

Every scam a citizen reports (through the tamper-evident ledger → NCRP packet)
can add one line to the national rules file. That line protects **every other
phone** on the next refresh. The system gets stronger with scale — the classic
network effect — but unlike Truecaller's crowd DB or a cloud model, **no
citizen's messages are collected to achieve it.** Only the verdict-relevant
identifiers (a reported UPI id, a scam number) propagate, and those come through
the official reporting rail, not surveillance.

## What is built vs what is architecture

Being straight, because judges will ask:

- **Built and demoable now:** on-device deterministic engine; the signed rules
  file bundled into the APK; the stateless verdict engine; the tamper-evident
  ledger; the NCRP-aligned packet; the in-app update mechanism (proves the
  "push to every phone" pathway with a real transport).
- **Designed, one endpoint from real:** `/intel/rules` serving a
  government-signed rules file, and the ledger forwarding reports to the I4C
  rail. Both are thin additions on top of what exists — no model to train, no
  data lake to build. That is the point: the scalable version is *less* code,
  not more.

## The procurement sentence

> Veris scales to every phone in India because it moves a few kilobytes of
> signed rules down and clean, tamper-evident reports up — never a model to run
> in the cloud and never a citizen's messages to collect. It makes the
> government's existing 1930/NCRP investment reach the citizen's lock screen.
