"""Work out what the user actually gave us.

Share-sheet input is messy: a whole SMS, a bare domain, a UPI id, a phone
number. Everything downstream depends on getting this right, so it is a
separate, separately-tested step.
"""

import re

from verdict import Subject

# A UPI VPA: <name>@<handle>. The handle is a bank/PSP alias (ybl, okaxis,
# paytm) and contains no dot -- that is exactly what separates
# "ramesh@okhdfcbank" from the email address "ramesh@gmail.com".
_VPA = re.compile(r"^[a-zA-Z0-9._-]{2,256}@[a-zA-Z][a-zA-Z0-9]{1,63}$")

# Indian mobile: optional +91 / 0 prefix, then 10 digits starting 6-9.
_PHONE = re.compile(r"^(?:\+?91[-\s]?|0)?[6-9]\d{9}$")

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

_URL_IN_TEXT = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)

# A bare domain typed without a scheme, e.g. "hdfcbank-secure.top".
_BARE_DOMAIN = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")


def classify(raw: str) -> Subject:
    """Turn raw shared text into a typed Subject.

    Order matters: a SHA-256 hash is also alphanumeric, and a URL can contain
    an '@'. Most specific patterns are tested first.
    """
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty input")

    if _SHA256.match(text):
        return Subject(type="apk_hash", value=text.lower())

    # Pull the first URL out of a longer message (the usual share-sheet case).
    found = _URL_IN_TEXT.search(text)
    if found:
        url = found.group(0).rstrip(".,)!\"'")
        if url.lower().startswith("www."):
            url = "http://" + url
        return Subject(type="url", value=url)

    compact = text.replace(" ", "")
    if _PHONE.match(compact):
        return Subject(type="phone", value=compact)

    if _VPA.match(text):
        return Subject(type="upi", value=text.lower())

    if _BARE_DOMAIN.match(text):
        return Subject(type="domain", value=text.lower())

    raise ValueError(f"could not classify input: {text[:80]!r}")
