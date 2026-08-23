"""Veris shared schema: verdicts and evidence.

Single source of truth for the backend. `verdict.ts` mirrors this for the
mobile app -- change both together.

Design rule this file exists to enforce (see CLAUDE.md): a `Verdict` is
produced ONLY by deterministic rules over `Signal`s. `Explanation` is prose
written by an LLM from those signals and can never alter the verdict.
"""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["safe", "suspicious", "likely_scam"]
SubjectType = Literal["url", "domain", "phone", "upi", "apk_hash", "email"]


def utc_now() -> str:
    """ISO-8601 UTC timestamp. Every signal is stamped with one."""
    return datetime.now(timezone.utc).isoformat()


class Signal(BaseModel):
    """One piece of evidence from one named source.

    `source` + `value` + `observed_at` is the citation shown in the app's
    evidence panel. A signal with no real source must never be created.
    """

    id: str  # stable machine id, e.g. "domain_age"
    source: str  # human-readable origin, e.g. "RDAP (registry)"
    value: str  # what was observed, e.g. "registered 4 days ago"
    observed_at: str = Field(default_factory=utc_now)
    weight: int = 0  # points this signal contributes to the score


class Subject(BaseModel):
    """What was checked."""

    type: SubjectType
    value: str


class Explanation(BaseModel):
    """LLM prose. Contains no verdict of its own."""

    english: str
    regional: str
    language: str  # e.g. "mr", "hi"
    generated_by: str  # e.g. "groq:llama-3.3-70b" or "template-fallback"


class VerdictResult(BaseModel):
    """The full, citable answer returned to the app."""

    subject: Subject
    verdict: Verdict
    score: int  # 0-100, higher = more suspicious
    signals: list[Signal]
    rules_fired: list[str]  # exact rule names that produced the verdict
    engine_version: str
    generated_at: str = Field(default_factory=utc_now)
    explanation: Explanation | None = None
