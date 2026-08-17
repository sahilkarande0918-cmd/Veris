# fixtures

Seed data so Veris runs with the network off. A live demo must never depend
on a network call.

| File | What | Refresh |
|---|---|---|
| `brands_in.json` | Legitimate Indian bank / UPI / govt / telecom domains. Allowlist **and** the comparison targets for homoglyph + typosquat detection. | by hand, carefully |
| `blocklists/phishtank.txt` | Seed snapshot, PhishTank format | `scripts/refresh_blocklists.py` |
| `blocklists/urlhaus.txt` | Seed snapshot, URLhaus (abuse.ch) | same |
| `blocklists/openphish.txt` | Seed snapshot, OpenPhish | same |
| `upi_reported.txt` | Locally reported scam UPI VPAs | by hand |
| `samples.json` | 10 known-bad + 10 known-good, the Phase 1 acceptance set | by hand |

## The blocklist entries are synthetic

The shipped blocklist and sample domains are **invented for this demo**. They
follow real scam naming patterns (brand + `-kyc` / `-secure-login`, cheap
TLDs) so the demo is realistic, but they are not accusations against any real
site. Run `scripts/refresh_blocklists.py` to replace them with the real
upstream feeds.

Two deliberate exceptions, because they *are* the attack rather than a guess
at one:

- `xn--hdfcbnk-6fg.com` -- punycode for a Cyrillic-`а` (U+0430) lookalike of
  `hdfcbank.com`. This is the Phase 6 adversarial case.
- `hdfcbank.com.secure-verify.top` -- a real brand as a *subdomain* of an
  attacker-controlled domain. Naive detectors that substring-match "is
  hdfcbank.com in the URL?" pass this. Veris does not.

## Adding a brand

A wrong entry in `brands_in.json` produces a wrong verdict in both directions:
a missing brand means its impersonations go uncaught, and a typo'd domain
allowlists an attacker. Verify against the official site before adding.
