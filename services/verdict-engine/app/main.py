"""Veris verdict engine HTTP API.

Phase 1: deterministic checks only. There is deliberately no model call in
this file -- the explanation layer arrives in Phase 2 and will only ever be
handed the evidence produced here.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from verdict import VerdictResult

from . import ENGINE_VERSION
from .checks import host_of, registered_domain, run_offline_checks
from .enrich import enrich, is_offline
from .explain import explain
from .rules import decide
from .subject import classify

app = FastAPI(title="Veris Verdict Engine", version=ENGINE_VERSION)


class CheckRequest(BaseModel):
    """Raw text from the share sheet, paste box, or scanner."""

    input: str
    explain: bool = True
    language: str = "mr"  # regional output: "mr" (Marathi) or "hi" (Hindi)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe. Also the 'is it running?' check in the README."""
    return {
        "status": "ok",
        "engine_version": ENGINE_VERSION,
        "mode": "offline" if is_offline() else "online",
    }


@app.post("/check", response_model=VerdictResult)
def check(request: CheckRequest) -> VerdictResult:
    """Classify the input, gather evidence, apply the rules, return the lot.

    The response carries every signal with its own {source, value,
    observed_at} citation and the exact rules that fired, so the verdict can
    be audited without trusting this service.
    """
    try:
        subject = classify(request.input)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    signals = run_offline_checks(subject.type, subject.value)

    host = host_of(subject.value) if subject.type in ("url", "domain") else ""
    if host:
        signals += enrich(subject.type, subject.value, host, registered_domain(host))

    verdict, score, rules_fired = decide(signals)

    result = VerdictResult(
        subject=subject,
        verdict=verdict,
        score=score,
        signals=signals,
        rules_fired=rules_fired,
        engine_version=ENGINE_VERSION,
    )

    # The verdict is fixed by this point. The explainer is handed a finished
    # result and can only attach prose to it.
    if request.explain:
        result.explanation = explain(result, request.language)
    return result
