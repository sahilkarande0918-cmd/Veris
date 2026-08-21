# Veris vs everyone else — and why a government would pick it

This is the honest landscape. It exists so the team can answer, on stage, the
one question that decides the hackathon: *"Truecaller and Google already do
this. Why you?"*

## The scale of the problem (use these numbers on stage)

- Indians lost **₹22,495 crore (~US$2.7bn) to cyber fraud in 2025**, across
  **2.81 million complaints** — up 24% in a year.
- Over six years, I4C attributes **₹52,976 crore** in cumulative losses.
- The 1930 helpline / cybercrime.gov.in has saved **₹7,130 crore across 23
  lakh complaints** — proof the national reporting rail works, and matters.
- In 2025 authorities deactivated **1.2M SIMs**, froze **1.33M mule
  accounts**, recovered **₹5,489 crore**.
- Nearly **46% of digital-arrest operations originate abroad** (Cambodia,
  Myanmar, Laos) — so blocking the source is out of reach; protecting the
  citizen at the moment of contact is the only lever that scales.

Sources: [I4C / Business Standard], [Sanchar Saathi], [ORF], [ScamWatchHQ 2026].

## What every existing solution is, and what it cannot do

| Product | What it is | The gap Veris exploits |
|---|---|---|
| **Truecaller** | Crowd-sourced caller ID + spam DB | A black box: "Spam" with no reason. Its DB is private and foreign-held. Doesn't read the *content* of an SMS/UPI/link. No path to the national reporting rail. |
| **Google Scam Detection / Fake-call detection** | On-device Gemini Nano on the call; RCS-based fake-call alerts | **Both** parties must be on Phone by Google + Google Messages + Contacts. English-first. Pixel-centric. Useless on the ₹8,000 Android most Indian victims carry. |
| **Bitdefender / Norton / Kaspersky / ESET** | Mobile security suites: link/SMS scanning, web protection | Foreign private cloud. Verdict is a proprietary score, not citable evidence. Subscription. Sends your data off-device. No India rails, no regional languages, no evidence trail. |
| **Password managers (1Password, Bitwarden)** | Won't autofill on a mismatched URL | Only protects a login form. Silent on a UPI request, a WhatsApp link, a vishing call, an APK. |
| **Authenticator apps / passkeys** | Stop stolen-credential reuse | Protect one account. Don't tell a scared person *"this message is a scam."** |

The pattern across all of them: **paste/observe → proprietary model → a score.**
None can answer *"how do you know?"* with named, timestamped, verifiable
evidence. None feed India's national reporting rails. Most are foreign,
cloud-based, English-only subscriptions.

## The technology gap the whole industry has

The best AI scam detectors hit ~96% in the lab and **drop to 45–50% in the
real world**. AI voice-scam volume rose **>1,200%** in 2025. A pure-model
approach is exactly the approach that degrades in the field — and a model that
is confidently wrong half the time is unusable for a government that has to
stand behind the verdict.

Veris's answer is the opposite bet: **the verdict is deterministic checks
against real sources; the model only explains.** That does not degrade in the
field, and every verdict is auditable. This is the single most important
sentence in the pitch.

## Why a government picks Veris specifically

A consumer wants "is this safe?". A government buyer wants six more things, and
Veris is built for all six where the competitors are built for none:

1. **Accountable, not a black box.** Every verdict ships its evidence with
   `{source, value, timestamp}` and the exact rules that fired. A public body
   can defend, audit, and FOIA-answer a Veris verdict. It cannot do that with
   Truecaller's score.

2. **Sovereign and on-device.** Judgments happen on the phone. Notification
   content is never transmitted or stored. No citizen data leaves the country
   or the device. That is a procurement requirement, not a nicety.

3. **It feeds the rails the government already built.** Veris produces an
   **NCRP/1930-aligned complaint packet** and deep-links to cybercrime.gov.in
   and Sanchar Saathi/Chakshu. It doesn't compete with I4C — it is a citizen
   front-end that pours clean, structured, tamper-evident reports *into* I4C.
   That is the difference between a product the government buys and a product
   the government builds around.

4. **Tamper-evident evidence.** The hash-chained ledger means a citizen's
   report is court-usable and cannot be quietly altered — by them, by us, or by
   anyone between. No competitor has this.

5. **Works for the actual victim.** Regional languages (Marathi/Hindi today,
   extensible), any Android, offline, no subscription. The ₹22,500-crore loss
   is concentrated in exactly the users Google's Pixel-and-English feature
   cannot reach.

6. **It scales without a data moat.** The detection rules are a small signed
   file, not a proprietary cloud model. The government can own the rules,
   publish updates to every phone in the country, and the network gets stronger
   as citizens report — without anyone harvesting citizen data to train a model.
   See `docs/SCALABILITY.md`.

## The one-line positioning

> Truecaller tells you a caller is spam. Google tells you a Pixel owner's call
> might be fake. **Veris tells any Indian, in their language, whether a message,
> link, UPI id, call or app is a scam — proves it with cited evidence, seals
> that evidence so it stands up as a complaint, and feeds it straight into
> India's own 1930 / NCRP system. On the phone, offline, owned by no foreign
> cloud.**

## Where we are honestly weaker, and the answer

- **Vishing (a convincing human voice).** No app stops a person who chooses to
  trust a voice. Our lever is the *number* (call screening against the reported
  list) and the *aftermath* (the moment they're told to pay a UPI id or open a
  link, Veris fires). Say this plainly; it's more credible than claiming to
  detect deepfake audio, which the whole industry does badly.
- **The blocklists and reported lists are seeds.** In production they are fed
  by the national rails and by citizen reports through the ledger. The
  architecture for that is real (`docs/SCALABILITY.md`); the seed data is
  labelled as seed data.
