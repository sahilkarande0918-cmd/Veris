"""Veris verdict engine HTTP API.

Phase 0: health only. The deterministic checks land in Phase 1.
"""

from fastapi import FastAPI

from . import ENGINE_VERSION

app = FastAPI(title="Veris Verdict Engine", version=ENGINE_VERSION)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe. Also the 'is it running?' check in the README."""
    return {"status": "ok", "engine_version": ENGINE_VERSION}
