"""The rule engine: signals in, verdict out.

This module is the reason Veris can answer "how do you know?". It is the ONLY
place a verdict is ever written. It contains no model call and no randomness --
the same signals always produce the same verdict, and it reports the exact
rules that fired.
"""

from verdict import Signal, Verdict

# Score bands. Deliberately conservative: we say "likely scam", never "scam".
#
# Signal weights are the single severity knob: a signal strong enough to
# convict alone (blocklist hit, homoglyph, reported VPA, Safe Browsing) is
# given a weight >= LIKELY_SCAM_AT rather than being listed separately here.
LIKELY_SCAM_AT = 60
SUSPICIOUS_AT = 30


def decide(signals: list[Signal]) -> tuple[Verdict, int, list[str]]:
    """Return (verdict, score 0-100, rules_fired).

    `rules_fired` is written for a human reading the evidence panel, and is
    what the Phase 2 explanation layer is allowed to talk about.
    """
    ids = {s.id for s in signals}
    score = min(100, sum(s.weight for s in signals))
    fired: list[str] = []

    # A verified brand domain that ALSO appears on a malware feed is a
    # compromised legitimate site, not a safe one. Reputation loses to evidence.
    allowlisted = "brand_allowlist" in ids
    incriminating = ids - {"brand_allowlist"}

    if allowlisted and not incriminating:
        return "safe", 0, ["brand_allowlist: domain matches a verified Indian brand"]

    if allowlisted and incriminating:
        fired.append(
            "allowlist_overridden: verified brand domain also carries "
            "incriminating signals; treating as possibly compromised"
        )

    for signal in sorted(signals, key=lambda s: -s.weight):
        if signal.id == "brand_allowlist":
            continue
        fired.append(f"{signal.id} (+{signal.weight}): {signal.value} [{signal.source}]")

    if not signals:
        return "safe", 0, ["no_signals: no local or remote source flagged this"]

    if score >= LIKELY_SCAM_AT:
        verdict: Verdict = "likely_scam"
    elif score >= SUSPICIOUS_AT:
        verdict = "suspicious"
    else:
        verdict = "safe"

    fired.append(f"score {score} -> {verdict} (likely_scam >= {LIKELY_SCAM_AT}, suspicious >= {SUSPICIOUS_AT})")
    return verdict, score, fired
