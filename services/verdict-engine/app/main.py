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
from .campaign import correlate
from .case_file import build_email_case
from .email_forensics import analyze_email, classify_label
from .privacy import log_preservation, mask_forensics, masking_enabled, retention_policy
from .enrich import enrich, is_offline
from .explain import explain
from .ledger import append, read_all, verify
from .packet import ComplaintDetails, build_packet
from .rules import decide
from . import security
from .subject import classify

app = FastAPI(title="Veris Verdict Engine", version=ENGINE_VERSION)

# Paths with no rate limit and no auth: liveness and the interactive docs.
# (/auth/device is token-exempt but IS rate-limited by IP -- handled below.)
_NO_LIMIT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}

# --- Input limits (DoS hardening). Sized to the real inputs: an SMS/URL is
# tiny, a QR screenshot small, an APK can be large. ---
MAX_INPUT_CHARS = 4096  # a shared SMS/link; anything larger is not a subject
MAX_QR_TEXT_CHARS = 8192  # a decoded QR payload (can be a long URL)
MAX_IMAGE_BYTES = 10 * 1024 * 1024  # QR screenshot
MAX_APK_BYTES = 200 * 1024 * 1024  # a large real APK
MAX_EML_BYTES = 25 * 1024 * 1024  # a large email with attachments
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


@app.middleware("http")
async def _auth_and_rate_limit(request: Request, call_next):
    """Gate API paths on a device token (when configured) and a rate limit.

    Auth is opt-in: it only bites when VERIS_AUTH_SECRET is set (a public host).
    Rate limiting always applies, keyed by device when authed else by client IP,
    so a single caller cannot burn a hosted engine's third-party quota.
    """
    path = request.url.path
    if request.method == "OPTIONS" or path in _NO_LIMIT_PATHS:
        return await call_next(request)

    ip = request.client.host if request.client else "anon"
    # Per-IP ceiling first, on every API path including /auth/device, so minting
    # many device tokens from one IP cannot multiply the allowance (F2).
    if not security.check_rate(f"ip:{ip}", "_ip_total"):
        return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)

    # Token registration needs no token (but was IP-limited just above).
    if path == "/auth/device":
        return await call_next(request)

    token = ""
    authz = request.headers.get("authorization", "")
    if authz[:7].lower() == "bearer ":
        token = authz[7:].strip()

    if security.auth_enabled():
        device = security.valid_token(token)
        if device is None:
            return JSONResponse({"detail": "missing or invalid device token"}, status_code=401)
        key = device
    else:
        key = ip

    if not security.check_rate(key, path):
        return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
    return await call_next(request)


class DeviceRegister(BaseModel):
    """A device identifier the app generates once and keeps (not a secret)."""

    device_id: str = Field(min_length=8, max_length=128)


@app.post("/auth/device")
def register_device(body: DeviceRegister) -> dict:
    """Issue this device a stateless API token.

    Always reachable. When VERIS_AUTH_SECRET is unset the token is accepted
    everywhere anyway, so the client flow is identical online and offline.
    """
    return {"token": security.mint_token(body.device_id), "auth_required": security.auth_enabled()}


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


@app.post("/check/email")
async def check_email(
    file: UploadFile | None = File(default=None),
    raw: Annotated[str | None, Form(max_length=MAX_EML_BYTES)] = None,
    language: Annotated[Language, Form()] = "mr",
    case: Annotated[bool, Form()] = False,
    mask: Annotated[bool | None, Form()] = None,
) -> dict:
    """Forensic analysis of a raw .eml [SIH26106].

    Fully offline: header/authentication forensics plus links routed through the
    SAME url engine become cited signals, the SAME `decide()` produces the
    verdict, and the result lands in the SAME hash-chained ledger. The email's
    structured forensics (auth results, originating IP, 5-label classification)
    ride alongside the standard VerdictResult.
    """
    if raw:
        content: str | bytes = raw
    elif file is not None:
        content = await _read_capped(file, MAX_EML_BYTES, "email")
    else:
        raise HTTPException(status_code=422, detail="provide an .eml file or raw text")

    signals, meta = analyze_email(content)
    if not signals:
        raise HTTPException(status_code=422, detail="could not parse an email from that input")

    verdict, score, rules_fired = decide(signals)
    result = VerdictResult(
        subject=Subject(type="email", value=meta.get("from_addr") or meta.get("message_id") or "email"),
        verdict=verdict,
        score=score,
        signals=signals,
        rules_fired=rules_fired,
        engine_version=ENGINE_VERSION,
    )
    result.explanation = explain(result, language)
    append("check", result.model_dump())

    label = classify_label(verdict, {s.id for s in signals})
    forensics = {**meta, "classification": label}
    response = {**result.model_dump(), "email_forensics": mask_forensics(forensics, masking_enabled(mask))}
    if case:
        # Prosecution-ready chain-of-custody case file (embeds the ledger status).
        case_file = build_email_case({**result.model_dump(), "email_forensics": forensics}, forensics)
        # Evidence-preservation logging: the export itself is auditable.
        log_preservation("case_file_export", case_file["chain_of_custody"]["evidence_digest"])
        response["case_file"] = case_file
    return response


@app.get("/privacy/policy")
def privacy_policy() -> dict:
    """The active privacy/retention/preservation policy [SIH26106 KC6]."""
    return retention_policy()


@app.post("/email/campaign")
async def email_campaign(files: list[UploadFile] = File(...)) -> dict:
    """Correlate several .eml into campaigns by shared infrastructure [SIH26106 #8].

    Graph-based (networkx): shared originating IP / ASN / X-Mailer / reply-to drop
    / relay / return-path cluster emails into a campaign with a confidence-based
    attribution (spoofed domain vs anonymized infra vs direct actor). Offline.
    """
    if len(files) < 2:
        raise HTTPException(status_code=422, detail="provide at least two .eml files to correlate")
    raws = [await _read_capped(f, MAX_EML_BYTES, "email") for f in files]
    return correlate(raws)
