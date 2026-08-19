"""Veris verdict engine HTTP API.

Phase 1: deterministic checks only. There is deliberately no model call in
this file -- the explanation layer arrives in Phase 2 and will only ever be
handed the evidence produced here.
"""

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel
from verdict import Subject, VerdictResult

from . import ENGINE_VERSION
from .apk import analyze as analyze_apk
from .checks import host_of, registered_domain, run_offline_checks
from .enrich import enrich, is_offline
from .explain import explain
from .ledger import append, read_all, verify
from .packet import ComplaintDetails, build_packet
from .rules import decide
from .subject import classify

app = FastAPI(title="Veris Verdict Engine", version=ENGINE_VERSION)


class CheckRequest(BaseModel):
    """Raw text from the share sheet, paste box, or scanner."""

    input: str
    explain: bool = True
    language: str = "mr"  # regional output: "mr" (Marathi) or "hi" (Hindi)
    record: bool = True  # append this check to the tamper-evident ledger


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

    if request.record:
        append("check", result.model_dump())
    return result


@app.get("/ledger/events")
def ledger_events() -> dict:
    """Every recorded event, oldest first. Backs the app's History screen."""
    return {"events": read_all()}


@app.get("/ledger/verify")
def ledger_verify() -> dict:
    """Walk the hash chain and report the first break, with the reason.

    This is the endpoint that makes the evidence trail worth anything: anyone
    can call it and see whether the log has been edited since it was written.
    """
    return verify()


@app.post("/ledger/report")
def ledger_report(complaint: ComplaintDetails) -> dict:
    """Record the user's complaint details and return an NCRP-aligned packet.

    Filing is the user's decision: this returns the packet to them and submits
    nothing anywhere.
    """
    append("report", complaint.model_dump())
    return build_packet(complaint)


@app.post("/check/apk", response_model=VerdictResult)
async def check_apk(file: UploadFile = File(...), language: str = "mr") -> VerdictResult:
    """Static analysis of an uploaded APK. The app is never installed or run.

    Permissions are facts read from the manifest, so the same deterministic
    rule engine decides here too -- there is no model in this path either.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=422, detail="expected a .apk file")

    with tempfile.TemporaryDirectory() as workdir:
        target = Path(workdir) / "upload.apk"
        target.write_bytes(await file.read())
        signals, meta = analyze_apk(target)

    verdict, score, rules_fired = decide(signals)
    result = VerdictResult(
        subject=Subject(type="apk_hash", value=meta["sha256"]),
        verdict=verdict,
        score=score,
        signals=signals,
        rules_fired=rules_fired + [f"apk package: {meta.get('package')}"],
        engine_version=ENGINE_VERSION,
    )
    result.explanation = explain(result, language)
    append("check", result.model_dump())
    return result
