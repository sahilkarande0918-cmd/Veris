"""Email threat forensics [SIH26106].

Turns a raw `.eml` into the SAME cited-signal evidence the rest of Veris runs
on, so a fraudulent email flows through the unchanged rule engine, explanation
layer and hash-chained ledger exactly like a URL or UPI id does.

Design rules kept here (see CLAUDE.md / the SIH26106 gap map in STATE.md):
- Header forensics are OFFLINE and deterministic: alignment/mismatch checks and
  reading the receiver's own Authentication-Results need no network. Live
  SPF/DKIM/DMARC re-validation is enrichment that degrades to [] (a later slice).
- Every finding is a `Signal{id, source, value, weight}`; the verdict is still
  produced by `rules.decide()`, never here. This module only gathers evidence.
- Links in the body are routed straight into the EXISTING `run_offline_checks`
  URL engine (homoglyph, blocklist, typosquat, ...). No new link pipeline.
"""

from __future__ import annotations

import re
from email import message_from_string
from email.message import EmailMessage
from email.policy import default
from email.utils import parseaddr

from verdict import Signal

from .checks import host_of, registered_domain, run_offline_checks

_URL = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_AUTH = {
    "spf": re.compile(r"\bspf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.IGNORECASE),
}
# Weight when an authentication mechanism reports failure. DMARC failing is the
# strongest single spoofing signal an email can carry.
_AUTH_FAIL_WEIGHT = {"dmarc": 35, "spf": 25, "dkim": 20}

# Deterministic language patterns = the brief's NLP table-stakes as rules. These
# ASSIST (modest weights) so a hard signal (auth fail, spoof) always dominates;
# they only tip a borderline email. (id, regex, weight, human description.)
_PATTERNS = [
    ("email_lang_urgency", r"(?:\burgent\b|immediately|within\s+\d+\s*hours?|\bexpir\w+|suspend\w*|\bblock(?:ed|ing)?\b|act now|final (?:notice|warning))", 15, "urgency / pressure language"),
    ("email_lang_credential_harvest", r"(?:verify your (?:account|kyc|identity)|confirm your (?:password|otp|pin)|update (?:your )?kyc|re-?activate|log ?in to (?:verify|confirm|secure))", 20, "credential / KYC-harvesting language"),
    ("email_lang_payment_diversion", r"(?:change (?:of )?(?:bank|account) details|updated (?:bank|account)|new account number|wire transfer|remittance|change the payment)", 25, "payment-diversion (BEC) language"),
    ("email_lang_fake_invoice", r"(?:invoice attached|outstanding (?:payment|invoice|balance)|overdue|payment (?:is )?due|proforma)", 20, "fake-invoice (BEC) language"),
]
_COMPILED = [(pid, re.compile(rx, re.IGNORECASE), w, desc) for pid, rx, w, desc in _PATTERNS]

# Brand / institution names a display-name commonly impersonates.
_BRANDS = {
    "hdfc", "icici", "sbi", "axis", "kotak", "paypal", "amazon", "microsoft",
    "google", "apple", "netflix", "income tax", "gst", "uidai", "aadhaar",
    "rbi", "npci", "paytm", "phonepe",
}


def parse_eml(raw: str | bytes) -> EmailMessage:
    """Parse raw .eml text into a message. Stdlib `email` IS the maintained
    parser -- no hand-rolling, and no extra dependency."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    return message_from_string(text, policy=default)


def _domain_of(header_value: str | None) -> str:
    if not header_value:
        return ""
    _name, addr = parseaddr(header_value)
    return addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""


def _is_public_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    if a in (10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    if a == 169 and b == 254:  # link-local
        return False
    return 0 < a < 240


def originating_ip(received: list[str]) -> str | None:
    """The earliest reliable sending node. Received headers are prepended, so
    the LAST one is closest to the origin; return the first public IP found
    scanning from the origin end."""
    for header in reversed(received):
        for ip in _IPV4.findall(header):
            if _is_public_ip(ip):
                return ip
    return None


def auth_results(msg: EmailMessage) -> dict[str, str]:
    """spf/dkim/dmarc outcomes read from the receiver's Authentication-Results
    (offline: this is the receiving server's own verdict, not ours to fake)."""
    blob = " ".join(msg.get_all("Authentication-Results", []))
    out: dict[str, str] = {}
    for mech, pattern in _AUTH.items():
        m = pattern.search(blob)
        if m:
            out[mech] = m.group(1).lower()
    return out


def header_signals(msg: EmailMessage) -> list[Signal]:
    """The offline header forensics: authentication outcomes, sender-field
    alignment, and reply-to redirection -- each a cited signal."""
    signals: list[Signal] = []

    # 1) Authentication-Results (SPF / DKIM / DMARC).
    for mech, outcome in auth_results(msg).items():
        failed = outcome in ("fail", "softfail", "none", "permerror", "temperror")
        signals.append(
            Signal(
                id=f"email_auth_{mech}",
                source="Authentication-Results header (receiving server)",
                value=f"{mech.upper()} = {outcome}",
                weight=_AUTH_FAIL_WEIGHT[mech] if failed else 0,
            )
        )

    from_dom = _domain_of(msg["From"])
    # 2) From vs Return-Path (envelope) mismatch -- classic spoofing tell.
    rp_dom = _domain_of(msg["Return-Path"])
    if from_dom and rp_dom and registered_domain(from_dom) != registered_domain(rp_dom):
        signals.append(
            Signal(
                id="email_from_returnpath_mismatch",
                source="From vs Return-Path header",
                value=f"From is {from_dom} but the envelope sender is {rp_dom}",
                weight=25,
            )
        )

    # 3) Reply-To pointing at a different domain -- redirects the victim's reply
    #    (a hallmark of business-email-compromise / invoice fraud).
    reply_dom = _domain_of(msg["Reply-To"])
    if from_dom and reply_dom and registered_domain(from_dom) != registered_domain(reply_dom):
        signals.append(
            Signal(
                id="email_replyto_mismatch",
                source="Reply-To vs From header",
                value=f"replies would go to {reply_dom}, not {from_dom}",
                weight=20,
            )
        )

    # 4) Originating IP (evidence now; geolocated in the origin/geo slice).
    ip = originating_ip(msg.get_all("Received", []))
    if ip:
        signals.append(
            Signal(
                id="email_originating_ip",
                source="Received header chain (earliest public hop)",
                value=ip,
                weight=0,
            )
        )
    return signals


def _links(msg: EmailMessage) -> list[str]:
    try:
        body = msg.get_body(preferencelist=("plain", "html"))
        text = body.get_content() if body else ""
    except (KeyError, LookupError, AttributeError):
        text = ""
    if not text:
        text = str(msg)
    seen: list[str] = []
    for url in _URL.findall(text):
        url = url.rstrip(".,)>\"'")
        if url not in seen:
            seen.append(url)
    return seen[:20]  # ponytail: cap; a mail with 100 links is itself a smell, but 20 covers demos


def link_signals(msg: EmailMessage) -> list[Signal]:
    """Route every link in the body through the EXISTING URL engine and merge.
    No new link pipeline -- the homoglyph/blocklist/typosquat checks just run."""
    signals: list[Signal] = []
    seen_ids: set[str] = set()
    for url in _links(msg):
        for sig in run_offline_checks("url", url):
            key = f"{sig.id}:{sig.value}"
            if key not in seen_ids:
                seen_ids.add(key)
                signals.append(sig)
    return signals


def _body_text(msg: EmailMessage) -> str:
    try:
        body = msg.get_body(preferencelist=("plain", "html"))
        text = body.get_content() if body else ""
    except (KeyError, LookupError, AttributeError):
        text = ""
    return f"{msg['Subject'] or ''}\n{text or str(msg)}"


def content_signals(msg: EmailMessage) -> list[Signal]:
    """The NLP table-stakes as deterministic rules: urgency, credential
    harvesting, payment diversion, fake invoice (BEC). Assist-weighted."""
    text = _body_text(msg)
    signals: list[Signal] = []
    for pid, pattern, weight, desc in _COMPILED:
        m = pattern.search(text)
        if m:
            signals.append(
                Signal(
                    id=pid,
                    source="email body language analysis",
                    value=f'{desc} (e.g. "{m.group(0).strip()[:60]}")',
                    weight=weight,
                )
            )
    return signals


def display_name_spoof(msg: EmailMessage, from_domain: str) -> Signal | None:
    """Display name asserts a brand the sending domain has nothing to do with."""
    name = (parseaddr(msg["From"] or "")[0] or "").lower()
    for brand in _BRANDS:
        if brand in name and brand.replace(" ", "") not in from_domain.replace("-", ""):
            return Signal(
                id="email_display_name_spoof",
                source="From display name vs sender domain",
                value=f'display name claims "{brand}" but the address domain is {from_domain or "unknown"}',
                weight=30,
            )
    return None


def sender_domain_signals(from_domain: str) -> list[Signal]:
    """Route the sender's own domain through the EXISTING engine so a deceptive
    or look-alike sender domain is caught the same way a link would be."""
    return run_offline_checks("domain", from_domain) if from_domain else []


def classify_label(verdict: str, signal_ids: set[str]) -> str:
    """The brief's 5-label taxonomy, derived DETERMINISTICALLY from which signals
    fired -- not by the model. Hard signals drive it, same as the verdict."""
    bec = signal_ids & {"email_lang_payment_diversion", "email_lang_fake_invoice"}
    spoofed = signal_ids & {
        "email_from_returnpath_mismatch",
        "email_display_name_spoof",
        "email_auth_dmarc",
        "email_auth_spf",
    }
    if verdict == "likely_scam":
        if bec:
            return "fraud-related"
        return "impersonated" if spoofed else "phishing"
    if verdict == "suspicious":
        return "suspicious"
    return "legitimate"


def analyze_email(raw: str | bytes) -> tuple[list[Signal], dict]:
    """Full offline analysis: (signals for the rule engine, forensic metadata)."""
    msg = parse_eml(raw)
    from_dom = _domain_of(msg["From"])
    signals = header_signals(msg) + content_signals(msg) + link_signals(msg) + sender_domain_signals(from_dom)
    spoof = display_name_spoof(msg, from_dom)
    if spoof:
        signals.append(spoof)

    from_name, from_addr = parseaddr(msg["From"] or "")
    meta = {
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": _domain_of(msg["From"]),
        "return_path": _domain_of(msg["Return-Path"]),
        "reply_to": _domain_of(msg["Reply-To"]),
        "subject": str(msg["Subject"] or ""),
        "message_id": str(msg["Message-ID"] or ""),
        "auth_results": auth_results(msg),
        "originating_ip": originating_ip(msg.get_all("Received", [])),
        "received_hops": len(msg.get_all("Received", [])),
        "links": _links(msg),
    }
    return signals, meta
