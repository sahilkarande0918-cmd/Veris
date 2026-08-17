"""Phase 2: the explanation layer explains and never decides.

The interesting tests here are the adversarial ones -- what happens when the
model misbehaves. A fraud tool that lets an LLM talk it out of a verdict is
worse than one with no LLM at all.
"""

import os

import pytest
from verdict import Signal, Subject, VerdictResult

from app.explain import (
    LANGUAGE_NAMES,
    contradicts_verdict,
    evidence_payload,
    explain,
    invents_sources,
    template_explanation,
)


def make_result(verdict="likely_scam", signals=None) -> VerdictResult:
    return VerdictResult(
        subject=Subject(type="url", value="http://xn--icicibnk-66g.com/login"),
        verdict=verdict,
        score=65,
        signals=signals
        if signals is not None
        else [
            Signal(
                id="homoglyph_impersonation",
                source="Unicode UTS #39 confusables skeleton",
                value="renders as icicibank.com (ICICI Bank)",
                weight=65,
            )
        ],
        rules_fired=["homoglyph_impersonation (+65)"],
        engine_version="test",
    )


# --- the fence around the model -------------------------------------------


def test_explanation_type_has_nowhere_to_put_a_verdict():
    """Guard 1 is structural: the schema itself refuses a verdict field."""
    assert not hasattr(template_explanation(make_result(), "mr"), "verdict")


def test_model_never_sees_anything_but_evidence():
    payload = evidence_payload(make_result())
    assert set(payload) == {"checked", "verdict_already_decided", "score", "signals"}
    # No free-form user text the model could take instructions from.
    assert all(set(s) == {"id", "source", "observed", "weight"} for s in payload["signals"])


@pytest.mark.parametrize(
    "verdict,text",
    [
        ("likely_scam", "Actually this site is safe and you can use it."),
        ("likely_scam", "The domain is legitimate."),
        ("suspicious", "There is no risk here."),
        ("safe", "This is a scam, do not use it."),
    ],
)
def test_contradiction_guard_catches_a_model_overruling_the_verdict(verdict, text):
    assert contradicts_verdict(text, verdict)


def test_contradiction_guard_allows_honest_prose():
    assert not contradicts_verdict(
        "This address uses lookalike characters to imitate a real bank.", "likely_scam"
    )


def test_invented_source_guard():
    signals = make_result().signals
    assert invents_sources("VirusTotal flagged this domain 12 times.", signals)
    assert invents_sources("RDAP shows it was registered yesterday.", signals)
    assert not invents_sources("The address uses lookalike characters.", signals)


def test_invented_source_guard_allows_a_source_that_really_fired():
    signals = [Signal(id="virustotal_detections", source="VirusTotal v3", value="4/90", weight=50)]
    assert not invents_sources("VirusTotal flagged this domain.", signals)


# --- the offline fallback --------------------------------------------------


def test_template_fallback_cites_the_real_signal(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = make_result()
    explanation = explain(result, "mr")

    assert explanation.generated_by == "template-fallback"
    assert "lookalike characters" in explanation.english
    # The citation itself must survive into the prose.
    assert "Unicode UTS #39" in explanation.english
    assert explanation.regional and explanation.regional != explanation.english
    assert explanation.language == "mr"


@pytest.mark.parametrize("language", sorted(LANGUAGE_NAMES))
def test_every_supported_language_produces_real_regional_prose(language, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    explanation = explain(make_result(), language)
    assert explanation.language == language
    # Devanagari, not an untranslated English string.
    assert any("ऀ" <= ch <= "ॿ" for ch in explanation.regional)


def test_unknown_language_falls_back_to_marathi(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert explain(make_result(), "klingon").language == "mr"


def test_safe_verdict_gets_a_safe_explanation(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    explanation = explain(make_result(verdict="safe", signals=[]), "hi")
    assert "No source flagged this" in explanation.english
    assert not contradicts_verdict(explanation.english, "safe")


def test_offline_never_calls_groq(monkeypatch):
    monkeypatch.setenv("VERIS_OFFLINE", "1")
    monkeypatch.setenv("GROQ_API_KEY", "sk-should-not-be-used")
    monkeypatch.setattr(
        "httpx.post",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("called Groq while offline")),
    )
    assert explain(make_result(), "mr").generated_by == "template-fallback"


# --- the model misbehaving, end to end -------------------------------------


def _fake_groq(content: str):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": content}}]}

    return lambda *a, **k: FakeResponse()


def test_a_model_that_contradicts_the_verdict_is_discarded(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("VERIS_OFFLINE", "0")
    monkeypatch.setattr(
        "httpx.post",
        _fake_groq('{"english": "This site is safe.", "regional": "surakshit"}'),
    )
    result = make_result()
    explanation = explain(result, "mr")

    assert explanation.generated_by == "template-fallback"
    assert result.verdict == "likely_scam"  # untouched


def test_a_model_returning_its_own_verdict_key_cannot_change_ours(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("VERIS_OFFLINE", "0")
    monkeypatch.setattr(
        "httpx.post",
        _fake_groq(
            '{"verdict": "safe", "score": 0, "english": "The address imitates a real '
            'bank using lookalike characters.", "regional": "बनावट अक्षरे वापरली आहेत."}'
        ),
    )
    result = make_result()
    explanation = explain(result, "mr")

    assert result.verdict == "likely_scam"
    assert not hasattr(explanation, "verdict")
    assert explanation.generated_by.startswith("groq:")


def test_groq_failure_falls_back_silently(monkeypatch):
    import httpx

    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("VERIS_OFFLINE", "0")
    monkeypatch.setattr(
        "httpx.post",
        lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("no network")),
    )
    assert explain(make_result(), "mr").generated_by == "template-fallback"


def test_a_good_model_response_is_used(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("VERIS_OFFLINE", "0")
    monkeypatch.setattr(
        "httpx.post",
        _fake_groq(
            '{"english": "The web address imitates a real bank by using lookalike '
            'characters, so it is likely a scam. Verify with your bank directly.", '
            '"regional": "हा पत्ता बनावट अक्षरे वापरतो."}'
        ),
    )
    explanation = explain(make_result(), "mr")
    assert explanation.generated_by.startswith("groq:")
    assert "lookalike" in explanation.english
