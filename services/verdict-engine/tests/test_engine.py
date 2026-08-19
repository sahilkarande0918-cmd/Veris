"""Edge cases the 20-sample acceptance set does not reach."""

import pytest
from verdict import Signal

from app.checks import bounded_levenshtein, host_of, registered_domain
from app.rules import decide
from app.subject import classify


@pytest.mark.parametrize(
    "raw,expected_type,expected_value",
    [
        # The share-sheet case: a whole SMS with a link buried in it.
        ("URGENT: your SBI account is blocked. Verify at http://sbi-kyc.top/x now", "url", "http://sbi-kyc.top/x"),
        ("www.hdfcbank-secure.top/login", "url", "http://www.hdfcbank-secure.top/login"),
        ("hdfcbank.com", "domain", "hdfcbank.com"),
        ("ramesh@okhdfcbank", "upi", "ramesh@okhdfcbank"),
        ("+91 98765 43210", "phone", "+919876543210"),
        ("9876543210", "phone", "9876543210"),
        ("0" * 64, "apk_hash", "0" * 64),
    ],
)
def test_classify(raw, expected_type, expected_value):
    subject = classify(raw)
    assert (subject.type, subject.value) == (expected_type, expected_value)


def test_email_is_not_mistaken_for_a_upi_id():
    """A VPA handle has no dot; an email domain does.

    Email is not a supported subject, so rejecting it outright is correct --
    far better than silently checking it against UPI scam lists.
    """
    with pytest.raises(ValueError):
        classify("ramesh@gmail.com")


def test_classify_rejects_junk():
    with pytest.raises(ValueError):
        classify("   ")


def test_trailing_punctuation_is_stripped_from_shared_links():
    assert classify("check this http://sbi-kyc.top/x.").value == "http://sbi-kyc.top/x"


@pytest.mark.parametrize(
    "a,b,expected",
    [("hdfcbank", "hdfcbank", 0), ("hdfcbnak", "hdfcbank", 2), ("icicibnk", "icicibank", 1)],
)
def test_bounded_levenshtein(a, b, expected):
    assert bounded_levenshtein(a, b) == expected


def test_bounded_levenshtein_gives_up_past_the_limit():
    assert bounded_levenshtein("paytm", "unionbankofindia") > 2


def test_registered_domain_handles_multi_part_suffixes():
    assert registered_domain("www.irctc.co.in") == "irctc.co.in"
    assert registered_domain("login.hdfcbank.com") == "hdfcbank.com"


def test_host_of_strips_www_and_port():
    assert host_of("https://WWW.Example.com:8443/path") == "example.com"


def test_brand_used_as_a_bare_subdomain_label_is_caught():
    """`hdfcbank.secure-verify.top` -- brand as a bare label, not a full domain.

    Covers the second branch of check_brand_as_subdomain, which the 20-sample
    set only exercises in its `hdfcbank.com.…` form.
    """
    from app.checks import check_brand_as_subdomain

    signals = check_brand_as_subdomain("hdfcbank.secure-verify.top")
    assert [s.id for s in signals] == ["brand_as_subdomain"]


def test_no_signals_is_safe():
    verdict, score, fired = decide([])
    assert (verdict, score) == ("safe", 0)
    assert fired


def test_allowlisted_domain_on_a_malware_feed_is_not_called_safe():
    """A compromised legitimate site is the case a naive allowlist gets wrong."""
    signals = [
        Signal(id="brand_allowlist", source="fixture", value="verified", weight=0),
        Signal(id="blocklist_hit", source="URLhaus", value="listed", weight=70),
    ]
    verdict, _, fired = decide(signals)
    assert verdict == "likely_scam"
    assert any("allowlist_overridden" in line for line in fired)


def test_score_is_capped_at_100():
    signals = [Signal(id=f"s{i}", source="x", value="y", weight=70) for i in range(3)]
    _, score, _ = decide(signals)
    assert score == 100


# --- Phase 6: adversarial URL structure and India grounding -----------------


def test_userinfo_deception_is_caught():
    """`hdfcbank.com@evil.top` is served by evil.top. Naive detectors miss it."""
    from app.checks import check_userinfo_deception

    signals = check_userinfo_deception("http://hdfcbank.com@secure-verify.top/login")
    assert [s.id for s in signals] == ["userinfo_deception"]
    assert signals[0].weight >= 60


def test_userinfo_without_a_brand_is_still_flagged_but_lower():
    from app.checks import check_userinfo_deception

    signals = check_userinfo_deception("http://someone@random-host.xyz/")
    assert [s.id for s in signals] == ["userinfo_present"]


def test_ordinary_url_has_no_userinfo_signal():
    from app.checks import check_userinfo_deception

    assert check_userinfo_deception("https://www.hdfcbank.com/") == []


def test_raw_ip_host_is_flagged():
    from app.checks import check_ip_host

    assert [s.id for s in check_ip_host("192.168.1.50")] == ["ip_address_host"]
    assert check_ip_host("hdfcbank.com") == []


def test_credit_offer_from_an_unregulated_domain_is_flagged():
    from app.checks import check_unregulated_lender

    signals = check_unregulated_lender(
        "instant-loan-approval-24x7.icu", "http://instant-loan-approval-24x7.icu/apply"
    )
    assert [s.id for s in signals] == ["unregulated_lender"]


def test_a_real_regulated_lender_is_not_flagged():
    """Bajaj Finserv is an RBI-regulated NBFC: a loan page there is fine."""
    from app.checks import check_unregulated_lender

    assert check_unregulated_lender("bajajfinserv.in", "https://bajajfinserv.in/personal-loan") == []
