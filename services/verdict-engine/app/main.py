"""Veris verdict engine HTTP API.

Phase 1: deterministic checks only. There is deliberately no model call in
this file -- the explanation layer arrives in Phase 2 and will only ever be
handed the evidence produced here.
"""

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
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

# --- Input limits (DoS hardening). Sized to the real inputs: an SMS/URL is
# tiny, a QR screenshot small, an APK can be large. ---
MAX_INPUT_CHARS = 4096  # a shared SMS/link; anything larger is not a subject
MAX_QR_TEXT_CHARS = 8192  # a decoded QR payload (can be a long URL)
MAX_IMAGE_BYTES = 10 * 1024 * 1024  # QR screenshot
MAX_APK_BYTES = 200 * 1024 * 1024  # a large real APK
MAX_BODY_BYTES = MAX_APK_BYTES + 1024 * 1024  # global request-body ceiling

# Output languages the explainer actually supports (see explain.py). Rejecting
# anything else at the boundary keeps unvalidated strings out of the pipeline.
Language = Literal["mr", "hi", "en"]


@app.middleware("http")
async def _limit_body_size(request: Request, call_next):
    """Reject oversized requests before they are buffered into memory.

    ponytail: a Content-Length guard. A chunked upload without the header slips
    past this, but the per-endpoint read caps below still bound memory use.
    """
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "request body too large"}, status_code=413)
    return await call_next(request)


async def _read_capped(file: UploadFile, cap: int, what: str) -> bytes:
    """Read an upload, refusing anything over `cap` bytes without loading it all.

    read(cap + 1) pulls at most one byte past the limit, so an oversized file is
    rejected having buffered only cap+1 bytes, never its full size.
    """
    data = await file.read(cap + 1)
    if len(data) > cap:
        raise HTTPException(status_code=413, detail=f"{what} exceeds {cap // (1024 * 1024)} MB limit")
    return data


class CheckRequest(BaseModel):
    """Raw text from the share sheet, paste box, or scanner."""

    input: str = Field(min_length=1, max_length=MAX_INPUT_CHARS)
    explain: bool = True
    language: Language = "mr"  # regional output: "mr" (Marathi) or "hi" (Hindi)
    record: bool = True  # append this check to the tamper-evident ledger


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe. Also the 'is it running?' check in the README."""
    return {
        "status": "ok",
        "engine_version": ENGINE_VERSION,
        "mode": "offline" if is_offline() else "online",
    }


def _run_check(text: str, explain_it: bool, language: str, record: bool) -> VerdictResult:
    """The core pipeline: classify -> evidence -> rules -> prose. Shared by
    every intake path (paste, share, QR) so they all get the identical, cited
    verdict."""
    try:
        subject = classify(text)
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
    if explain_it:
        result.explanation = explain(result, language)

    if record:
        append("check", result.model_dump())
    return result


@app.post("/check", response_model=VerdictResult)
def check(request: CheckRequest) -> VerdictResult:
    """Classify the input, gather evidence, apply the rules, return the lot.

    The response carries every signal with its own {source, value,
    observed_at} citation and the exact rules that fired, so the verdict can
    be audited without trusting this service.
    """
    return _run_check(request.input, request.explain, request.language, request.record)


@app.post("/check/qr", response_model=VerdictResult)
async def check_qr(
    file: UploadFile | None = File(default=None),
    text: Annotated[str | None, Form(max_length=MAX_QR_TEXT_CHARS)] = None,
    language: Annotated[Language, Form()] = "mr",
) -> VerdictResult:
    """Judge what a QR actually contains, then run the SAME engine on it.

    Two ways in, one pipeline:
    - `text`: the phone's camera already decoded the QR on-device (the common
      path); send the payload string.
    - `file`: an image to decode server-side (used by scripts and tests).

    Either way, a UPI QR is judged on the payee address that receives the money
    (`pa`), not the merchant name it claims (`pn`), which an attacker sets
    freely.
    """
    from .qr import decode_qr, subject_from_qr

    if text:
        qr_text = text.strip()
    elif file is not None:
        if file.content_type and not file.content_type.startswith("image/"):
            raise HTTPException(status_code=422, detail="expected an image file")
        qr_text = decode_qr(await _read_capped(file, MAX_IMAGE_BYTES, "image"))
    else:
        qr_text = None
    if not qr_text:
        raise HTTPException(status_code=422, detail="no QR payload found")
    return _run_check(subject_from_qr(qr_text), True, language, True)


@app.get("/ledger/events")
def ledger_events() -> dict:
    """Every recorded event, oldest first. Backs the app's History screen."""
    return {"events": read_all()}


def _demo_enabled() -> bool:
    """The tamper demo controls only exist when explicitly turned on."""
    import os

    return os.getenv("VERIS_DEMO", "0") == "1"


@app.post("/ledger/dev/tamper")
def ledger_tamper() -> dict:
    """DEMO ONLY (VERIS_DEMO=1): break the chain so tamper-detection is visible."""
    from .ledger import demo_tamper

    if not _demo_enabled():
        raise HTTPException(status_code=404, detail="not found")
    return demo_tamper()


@app.post("/ledger/dev/rebuild")
def ledger_rebuild() -> dict:
    """DEMO ONLY (VERIS_DEMO=1): re-seal the chain so it verifies green again."""
    from .ledger import demo_rebuild

    if not _demo_enabled():
        raise HTTPException(status_code=404, detail="not found")
    return demo_rebuild()


@app.get("/ledger/verify")
def ledger_verify() -> dict:
    """Walk the hash chain and report the first break, with the reason.

    This is the endpoint that makes the evidence trail worth anything: anyone
    can call it and see whether the log has been edited since it was written.
    """
    return verify()


_RULES_PATH = Path(__file__).resolve().parents[3] / "fixtures" / "ondevice_rules.json"


@app.get("/intel/rules")
def intel_rules() -> dict:
    """The national on-device rules file, plus a version hash.

    This is the distribution half of the scalability design (docs/SCALABILITY.md):
    the phone caches this and re-checks the `version` to know when a newer set of
    reported ids/hosts is available -- so a scam id reported through 1930 today
    can protect every phone tomorrow, with no app update and no model to run.

    The rules are the SAME deterministic checks the phone already ships; only a
    few kilobytes move, and no citizen data is collected to produce them.
    """
    raw = _RULES_PATH.read_bytes()
    version = hashlib.sha256(raw).hexdigest()[:16]
    return {"version": version, "rules": json.loads(raw)}


@app.post("/ledger/report")
def ledger_report(complaint: ComplaintDetails) -> dict:
    """Record the user's complaint details and return an NCRP-aligned packet.

    Filing is the user's decision: this returns the packet to them and submits
    nothing anywhere.
    """
    append("report", complaint.model_dump())
    return build_packet(complaint)


@app.post("/check/apk", response_model=VerdictResult)
async def check_apk(file: UploadFile = File(...), language: Language = "mr") -> VerdictResult:
    """Static analysis of an uploaded APK. The app is never installed or run.

    Permissions are facts read from the manifest, so the same deterministic
    rule engine decides here too -- there is no model in this path either.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=422, detail="expected a .apk file")

    payload = await _read_capped(file, MAX_APK_BYTES, "APK")
    with tempfile.TemporaryDirectory() as workdir:
        target = Path(workdir) / "upload.apk"
        target.write_bytes(payload)
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
