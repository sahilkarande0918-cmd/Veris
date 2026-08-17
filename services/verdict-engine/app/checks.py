"""Deterministic offline checks.

Every function here answers a question with local data and returns `Signal`s
carrying their own citation. No network, no model, no guessing. These are the
checks that must keep working when the venue wifi dies on stage.
"""

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import confusables
import tldextract
from verdict import Signal

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"

# suffix_list_urls=() pins tldextract to its bundled Public Suffix List
# snapshot, so it never reaches for the network mid-demo.
_extract = tldextract.TLDExtract(suffix_list_urls=())

_BLOCKLISTS = {
    "PhishTank (local snapshot)": "blocklists/phishtank.txt",
    "URLhaus / abuse.ch (local snapshot)": "blocklists/urlhaus.txt",
    "OpenPhish (local snapshot)": "blocklists/openphish.txt",
}


def _read_lines(relative: str) -> list[str]:
    path = FIXTURES / relative
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


@lru_cache(maxsize=1)
def load_brands() -> list[dict]:
    """Legitimate Indian brand domains. Allowlist and comparison targets."""
    data = json.loads((FIXTURES / "brands_in.json").read_text(encoding="utf-8"))
    return data["brands"]


@lru_cache(maxsize=1)
def _brand_index() -> dict[str, str]:
    """domain -> brand name, flattened for O(1) lookup."""
    return {d: b["name"] for b in load_brands() for d in b["domains"]}


@lru_cache(maxsize=1)
def _blocklist_index() -> dict[str, str]:
    """Normalised blocklist entry -> source name."""
    index: dict[str, str] = {}
    for source, relative in _BLOCKLISTS.items():
        for entry in _read_lines(relative):
            index.setdefault(_normalise_url(entry), source)
            index.setdefault(host_of(entry), source)
    return index


@lru_cache(maxsize=1)
def _reported_vpas() -> set[str]:
    return {v.lower() for v in _read_lines("upi_reported.txt")}


def _normalise_url(url: str) -> str:
    """Scheme- and case-insensitive form, so http/https variants both match."""
    stripped = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url.strip())
    return stripped.rstrip("/").lower()


def host_of(value: str) -> str:
    """Hostname from a URL or bare domain. Lowercased, no port, no 'www.'."""
    raw = value if "://" in value else f"http://{value}"
    host = (urlsplit(raw).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def registered_domain(host: str) -> str:
    """Registrable domain via the Public Suffix List.

    Falls back to the full host when the suffix is unknown to the bundled PSL,
    so an exotic TLD degrades to a usable value instead of an empty string.
    """
    return _extract(host).top_domain_under_public_suffix or host


def _decoded(host: str) -> str:
    """Unicode form of a punycode host, so xn--… is compared as it *looks*."""
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except (UnicodeError, UnicodeDecodeError):
        return host


def bounded_levenshtein(a: str, b: str, limit: int = 2) -> int:
    """Edit distance, giving up once it provably exceeds `limit`.

    ponytail: 10 lines of textbook DP instead of a rapidfuzz dependency --
    no Unicode data table involved, unlike the confusables mapping. Swap for
    rapidfuzz if this ever runs over a list long enough to matter.
    """
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            )
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def check_blocklists(subject_value: str) -> list[Signal]:
    """Exact URL or host match against the shipped feed snapshots."""
    index = _blocklist_index()
    for key in (_normalise_url(subject_value), host_of(subject_value)):
        if key and key in index:
            return [
                Signal(
                    id="blocklist_hit",
                    source=index[key],
                    value=f"{key} is listed as malicious",
                    weight=70,
                )
            ]
    return []


def check_brand_allowlist(host: str) -> list[Signal]:
    """Exact match on a known-good brand domain. Ends the investigation."""
    domain = registered_domain(host)
    name = _brand_index().get(domain) or _brand_index().get(host)
    if name:
        return [
            Signal(
                id="brand_allowlist",
                source="Veris curated Indian brand list (fixtures/brands_in.json)",
                value=f"{domain} is the verified domain of {name}",
                weight=0,
            )
        ]
    return []


def check_homoglyph(host: str) -> list[Signal]:
    """Unicode UTS #39 confusable-skeleton match against a real brand.

    Catches the attack a substring check cannot see: a domain that *renders*
    as a bank's name using Cyrillic or Greek lookalikes.
    """
    domain = registered_domain(_decoded(host))
    if domain in _brand_index():
        return []

    for candidate in confusables.normalize(domain):
        brand = _brand_index().get(candidate)
        if brand and candidate != domain:
            return [
                Signal(
                    id="homoglyph_impersonation",
                    source="Unicode UTS #39 confusables skeleton",
                    value=(
                        f"{domain!r} renders as {candidate!r} ({brand}) "
                        "using lookalike characters"
                    ),
                    weight=65,
                )
            ]
    return []


def check_typosquat(host: str) -> list[Signal]:
    """Levenshtein <= 2 against a brand domain, e.g. hdfcbnak.com."""
    domain = registered_domain(host)
    if domain in _brand_index():
        return []

    label = domain.split(".")[0]
    # Short labels collide by chance; below 6 chars this is all false positives.
    if len(label) < 6:
        return []

    for brand_domain, brand in _brand_index().items():
        brand_label = brand_domain.split(".")[0]
        distance = bounded_levenshtein(label, brand_label)
        if 0 < distance <= 2:
            return [
                Signal(
                    id="typosquat",
                    source="Levenshtein distance vs Veris curated brand list",
                    value=(
                        f"{domain!r} is {distance} edit(s) from "
                        f"{brand_domain!r} ({brand})"
                    ),
                    weight=45,
                )
            ]
    return []


def check_brand_as_subdomain(host: str) -> list[Signal]:
    """A real brand domain hidden in the subdomain of an attacker's domain.

    `hdfcbank.com.secure-verify.top` passes any naive "does the URL contain
    hdfcbank.com?" check. The registrable domain is what actually serves it.
    """
    domain = registered_domain(host)
    if domain in _brand_index():
        return []

    prefix = host[: -len(domain)].rstrip(".") if host.endswith(domain) else host
    for brand_domain, brand in _brand_index().items():
        if brand_domain in prefix or brand_domain.split(".")[0] == prefix.split(".")[-1]:
            return [
                Signal(
                    id="brand_as_subdomain",
                    source="Public Suffix List (registrable-domain comparison)",
                    value=(
                        f"looks like {brand} but is actually served by {domain!r}"
                    ),
                    weight=55,
                )
            ]
    return []


def check_upi(vpa: str) -> list[Signal]:
    """VPA format validation plus the locally reported scam list."""
    signals: list[Signal] = []
    vpa = vpa.lower()

    if vpa in _reported_vpas():
        signals.append(
            Signal(
                id="upi_reported",
                source="Veris locally reported VPA list (fixtures/upi_reported.txt)",
                value=f"{vpa} has been reported as used in scams",
                weight=70,
            )
        )

    if not re.match(r"^[a-z0-9._-]{2,256}@[a-z][a-z0-9]{1,63}$", vpa):
        signals.append(
            Signal(
                id="upi_malformed",
                source="NPCI UPI VPA format rules",
                value=f"{vpa} is not a well-formed UPI address",
                weight=30,
            )
        )
    return signals


def run_offline_checks(subject_type: str, value: str) -> list[Signal]:
    """Every offline check that applies to this subject."""
    if subject_type == "upi":
        return check_upi(value)

    if subject_type not in ("url", "domain"):
        return []

    host = host_of(value)
    if not host:
        return []

    signals = check_blocklists(value)

    allowlisted = check_brand_allowlist(host)
    if allowlisted:
        # A verified brand domain cannot also be impersonating itself.
        return signals + allowlisted

    for check in (check_homoglyph, check_typosquat, check_brand_as_subdomain):
        signals.extend(check(host))
    return signals
