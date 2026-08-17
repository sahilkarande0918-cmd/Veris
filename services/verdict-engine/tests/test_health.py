"""Phase 0 checks: the service answers, and the shared schema is reachable."""

from fastapi.testclient import TestClient

from app import ENGINE_VERSION
from app.main import app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "engine_version": ENGINE_VERSION}


def test_shared_schema_is_importable_and_stamps_signals():
    """The sys.path wiring in app/__init__.py is the thing under test here."""
    from verdict import Signal, Subject, VerdictResult

    result = VerdictResult(
        subject=Subject(type="url", value="http://example.test"),
        verdict="safe",
        score=0,
        signals=[Signal(id="stub", source="fixture", value="none")],
        rules_fired=[],
        engine_version=ENGINE_VERSION,
    )

    # Every signal must carry a timestamp without the caller remembering to set one.
    assert result.signals[0].observed_at.endswith("+00:00")
    assert result.explanation is None
