"""The explanation layer. Writes prose. Decides nothing.

The verdict arrives here already decided by `rules.decide()`. This module's
only job is to say, in a human's own language, what the evidence was.

Three guards keep it honest, because an LLM in a fraud tool is a liability
unless it is fenced in:

1. **No verdict field.** `Explanation` has nowhere to put one, and any
   `verdict` key the model returns is dropped on the floor.
2. **Contradiction check.** Prose that argues against the verdict it is
   supposed to be explaining is discarded.
3. **Invented-source check.** If the text name-drops VirusTotal, RDAP or
   PhishTank when no such signal was gathered, it is discarded.

On any failure -- bad key, dead network, guard trip -- we fall back to a
deterministic template built from the same signals. The fallback is not a
degraded mode we tolerate; it is the offline demo path.
"""

import json
import os

import httpx
from verdict import Explanation, Signal, VerdictResult

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# Groq retired llama-3.3-70b-versatile on 2026-08-16 and points free-tier
# users at gpt-oss-120b. Override with GROQ_MODEL if your account differs.
DEFAULT_MODEL = "openai/gpt-oss-120b"

LANGUAGE_NAMES = {"mr": "Marathi", "hi": "Hindi"}

# Prose that would contradict the verdict it is meant to explain.
_CONTRADICTIONS = {
    "likely_scam": ("is safe", "is legitimate", "no risk", "safe to use", "trustworthy", "is genuine"),
    "suspicious": ("is safe", "is legitimate", "no risk", "safe to use"),
    "safe": ("is a scam", "is fraud", "phishing site", "do not use"),
}

# If the prose mentions one of these, a matching signal must exist.
_SOURCE_WORDS = frozenset(
    {"virustotal", "safe browsing", "phishtank", "urlhaus", "openphish", "rdap", "whois", "certificate"}
)

_VERDICT_LINES = {
    "likely_scam": {
        "en": "This is likely a scam. Do not enter personal details, an OTP, or make any payment. Verify independently before you act.",
        "mr": "ही बहुधा फसवणूक आहे. कोणतीही वैयक्तिक माहिती किंवा OTP देऊ नका, पैसे पाठवू नका. कृती करण्यापूर्वी स्वतंत्रपणे खात्री करा.",
        "hi": "यह संभवतः धोखाधड़ी है। कोई व्यक्तिगत जानकारी या OTP न दें, भुगतान न करें। कार्रवाई से पहले स्वतंत्र रूप से जाँच करें।",
    },
    "suspicious": {
        "en": "This looks suspicious. Treat it with caution and check through the official app or website before acting.",
        "mr": "हे संशयास्पद वाटते. सावधगिरी बाळगा आणि अधिकृत ॲप किंवा संकेतस्थळावरून खात्री करा.",
        "hi": "यह संदिग्ध लगता है। सावधानी बरतें और आधिकारिक ऐप या वेबसाइट से जाँच करें।",
    },
    "safe": {
        "en": "No source flagged this. Stay alert anyway: never share an OTP with anyone.",
        "mr": "कोणत्याही स्रोताने याला धोकादायक ठरवलेले नाही. तरीही सावध रहा: OTP कोणालाही सांगू नका.",
        "hi": "किसी स्रोत ने इसे खतरनाक नहीं बताया। फिर भी सतर्क रहें: OTP किसी को न बताएं।",
    },
}

_SIGNAL_LINES = {
    "blocklist_hit": {
        "en": "It appears on a published list of malicious sites.",
        "mr": "हे संकेतस्थळ धोकादायक संकेतस्थळांच्या प्रसिद्ध यादीत आहे.",
        "hi": "यह वेबसाइट खतरनाक साइटों की प्रकाशित सूची में दर्ज है।",
    },
    "homoglyph_impersonation": {
        "en": "The address uses lookalike characters so it reads like a real bank's name without being it.",
        "mr": "या पत्त्यात खऱ्या बँकेच्या नावासारखी दिसणारी बनावट अक्षरे वापरली आहेत.",
        "hi": "इस पते में असली बैंक के नाम जैसे दिखने वाले नकली अक्षर इस्तेमाल हुए हैं।",
    },
    "brand_as_subdomain": {
        "en": "The brand name appears in the address, but the site is actually run from a different domain.",
        "mr": "पत्त्यात ब्रँडचे नाव दिसते, पण संकेतस्थळ प्रत्यक्षात दुसऱ्याच डोमेनवरून चालवले जाते.",
        "hi": "पते में ब्रांड का नाम दिखता है, पर साइट असल में किसी और डोमेन से चलाई जा रही है।",
    },
    "typosquat": {
        "en": "The address is only a character or two away from a real bank's address.",
        "mr": "हा पत्ता खऱ्या बँकेच्या पत्त्यापेक्षा फक्त एक-दोन अक्षरांनी वेगळा आहे.",
        "hi": "यह पता असली बैंक के पते से सिर्फ एक-दो अक्षर अलग है।",
    },
    "upi_reported": {
        "en": "This UPI ID has been reported as used in scams.",
        "mr": "हा UPI आयडी फसवणुकीसाठी वापरल्याची तक्रार नोंदवली आहे.",
        "hi": "इस UPI आईडी की धोखाधड़ी में उपयोग की शिकायत दर्ज है।",
    },
    "upi_malformed": {
        "en": "This UPI ID is not in a valid format.",
        "mr": "हा UPI आयडी योग्य स्वरूपात नाही.",
        "hi": "यह UPI आईडी सही प्रारूप में नहीं है।",
    },
    "brand_allowlist": {
        "en": "The address matches the verified official domain.",
        "mr": "हा पत्ता अधिकृत, पडताळलेल्या डोमेनशी जुळतो.",
        "hi": "यह पता सत्यापित आधिकारिक डोमेन से मेल खाता है।",
    },
    "safe_browsing_hit": {
        "en": "Google Safe Browsing lists this address as dangerous.",
        "mr": "Google Safe Browsing ने हा पत्ता धोकादायक म्हणून नोंदवला आहे.",
        "hi": "Google Safe Browsing ने इस पते को खतरनाक बताया है।",
    },
    "virustotal_detections": {
        "en": "Multiple security vendors flagged this domain.",
        "mr": "अनेक सुरक्षा कंपन्यांनी हे डोमेन धोकादायक ठरवले आहे.",
        "hi": "कई सुरक्षा कंपनियों ने इस डोमेन को खतरनाक बताया है।",
    },
    "domain_age": {
        "en": "The domain was registered very recently, which is unusual for a real bank.",
        "mr": "हे डोमेन अगदी अलीकडे नोंदवले गेले आहे, जे खऱ्या बँकेसाठी असामान्य आहे.",
        "hi": "यह डोमेन बहुत हाल में पंजीकृत हुआ है, जो असली बैंक के लिए असामान्य है।",
    },
}


def _line(signal_id: str, language: str) -> str | None:
    entry = _SIGNAL_LINES.get(signal_id)
    return entry.get(language) if entry else None


def template_explanation(result: VerdictResult, language: str) -> Explanation:
    """Deterministic prose built from the signals. No network, no model.

    This is the offline demo path, so it has to read well, not merely exist.
    """
    english = [_VERDICT_LINES[result.verdict]["en"]]
    regional = [_VERDICT_LINES[result.verdict][language]]

    for signal in sorted(result.signals, key=lambda s: -s.weight):
        if line_en := _line(signal.id, "en"):
            english.append(f"{line_en} ({signal.source}: {signal.value})")
            regional.append(_line(signal.id, language) or line_en)

    if len(english) == 1:
        english.append("No local blocklist, brand-impersonation, or format check flagged this.")

    return Explanation(
        english=" ".join(english),
        regional=" ".join(regional),
        language=language,
        generated_by="template-fallback",
    )


def evidence_payload(result: VerdictResult) -> dict:
    """Exactly what the model is allowed to see: the evidence, nothing else.

    No raw user text, no free-form context it could take instructions from.
    """
    return {
        "checked": f"{result.subject.type}: {result.subject.value}",
        "verdict_already_decided": result.verdict,
        "score": result.score,
        "signals": [
            {"id": s.id, "source": s.source, "observed": s.value, "weight": s.weight}
            for s in result.signals
        ],
    }


def contradicts_verdict(text: str, verdict: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in _CONTRADICTIONS.get(verdict, ()))


def invents_sources(text: str, signals: list[Signal]) -> bool:
    """True if the prose cites a source that produced no signal."""
    lowered = text.lower()
    gathered = " ".join(f"{s.id} {s.source} {s.value}" for s in signals).lower()
    return any(word in lowered and word not in gathered for word in _SOURCE_WORDS)


def _prompt(payload: dict, language: str, stricter: bool) -> list[dict]:
    language_name = LANGUAGE_NAMES.get(language, "Marathi")
    system = (
        "You are a fraud-analyst writing assistant for Indian users. You are given "
        "the EVIDENCE and a verdict that has ALREADY been decided by a deterministic "
        "rule engine. You do not decide anything.\n"
        "Rules:\n"
        "- Explain only the signals you are given. Never invent a source, a number, "
        "a statistic, or a fact that is not in the evidence.\n"
        "- Never contradict, re-judge, soften, or escalate the given verdict.\n"
        "- Never name a security service that is not present in the evidence.\n"
        "- Say 'likely' and advise the user to verify. Never accuse a named company "
        "of a crime.\n"
        "- Plain words a non-technical person understands. No markdown, 3-4 sentences.\n"
        f"Return ONLY a JSON object: {{\"english\": \"...\", \"regional\": \"...\"}} "
        f"where 'regional' is written in {language_name}."
    )
    if stricter:
        system += (
            "\nYour previous answer broke a rule (it contradicted the verdict or "
            "cited a source not in the evidence). Stay strictly inside the evidence."
        )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]


def _call_groq(payload: dict, language: str, stricter: bool) -> dict | None:
    key = os.getenv("GROQ_API_KEY")
    if not key:
        return None
    try:
        response = httpx.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": os.getenv("GROQ_MODEL", DEFAULT_MODEL),
                "messages": _prompt(payload, language, stricter),
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            },
            timeout=15.0,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
    except (httpx.HTTPError, KeyError, IndexError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    # Whatever else it returned -- including a 'verdict' key -- is discarded here.
    english, regional = parsed.get("english"), parsed.get("regional")
    if not isinstance(english, str) or not isinstance(regional, str):
        return None
    if not english.strip() or not regional.strip():
        return None
    return {"english": english.strip(), "regional": regional.strip()}


def explain(result: VerdictResult, language: str = "mr") -> Explanation:
    """Explain the evidence. Falls back to the template on any problem."""
    from .enrich import is_offline

    language = language if language in LANGUAGE_NAMES else "mr"

    if is_offline() or not os.getenv("GROQ_API_KEY"):
        return template_explanation(result, language)

    payload = evidence_payload(result)
    for attempt in range(2):
        drafted = _call_groq(payload, language, stricter=attempt > 0)
        if not drafted:
            break
        combined = f"{drafted['english']} {drafted['regional']}"
        if contradicts_verdict(combined, result.verdict):
            continue
        if invents_sources(drafted["english"], result.signals):
            continue
        return Explanation(
            english=drafted["english"],
            regional=drafted["regional"],
            language=language,
            generated_by=f"groq:{os.getenv('GROQ_MODEL', DEFAULT_MODEL)}",
        )

    return template_explanation(result, language)
