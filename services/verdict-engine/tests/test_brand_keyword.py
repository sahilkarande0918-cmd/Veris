"""Brand/agency name grafted onto a throwaway domain (deterministic)."""
from app.checks import check_brand_keyword_in_domain, run_offline_checks


def _ids(signals):
    return {s.id for s in signals}


def test_bank_name_plus_action_word_flags_strongly():
    sig = check_brand_keyword_in_domain("icici-verify-kyc.co")
    assert sig and sig[0].id == "brand_keyword_in_domain"
    assert sig[0].weight == 65  # brand keyword + phishing cue
    assert "icici" in sig[0].value


def test_govt_agency_name_flags():
    sig = check_brand_keyword_in_domain("echallan-parivahan.in")
    assert sig and sig[0].weight == 50  # agency name, no action word


def test_official_domain_is_not_flagged():
    assert check_brand_keyword_in_domain("icicibank.com") == []


def test_incidental_substring_is_not_flagged():
    # 'axis' brand keyword must match as a whole token, not inside 'taxishare'
    assert check_brand_keyword_in_domain("taxishare.example.com") == []


def test_wired_into_offline_pipeline():
    assert "brand_keyword_in_domain" in _ids(
        run_offline_checks("url", "http://sbi-rewards.in/claim")
    )
