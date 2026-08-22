"""Presence of this file puts the service root on sys.path, so `import app`
works when pytest is run from anywhere.

Importing `app` here also wires `packages/shared` onto sys.path (see
app/__init__.py), so a test module can `from verdict import ...` regardless of
which test file pytest happens to collect first.
"""

import pytest

import app  # noqa: F401


@pytest.fixture(autouse=True)
def isolated_ledger(tmp_path, monkeypatch):
    """Point every test at a throwaway ledger.

    /check appends to the ledger, so without this the test suite would write
    real records into the developer's data/ledger.jsonl on every run.
    """
    monkeypatch.setenv("VERIS_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """The rate limiter holds process-wide state; clear it between tests so
    request counts don't accumulate across the session."""
    from app import security

    security.reset_rate_limits()
    yield
