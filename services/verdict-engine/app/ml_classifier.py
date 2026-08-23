"""ML phishing-likelihood as ONE cited signal [SIH26106, Decision 1].

Loads the committed offline TF-IDF + LogReg model and turns an email's text into
a single `ml_phishing_likelihood` signal. Its weight is capped so it can nudge a
borderline verdict but never override a hard signal (auth fail, spoof, blocklist)
-- the model contributes, the rules decide. Degrades to None if the model or
scikit-learn is absent, so the engine still runs.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from verdict import Signal

_MODEL_PATH = Path(__file__).resolve().parent / "models" / "email_clf.joblib"
# Max points the model can add: below the strongest hard signals so it tips
# borderline cases without ever deciding on its own.
_MAX_WEIGHT = 30


@lru_cache(maxsize=1)
def _model():
    try:
        import joblib

        return joblib.load(_MODEL_PATH)
    except Exception:  # noqa: BLE001 - no model / no sklearn -> just skip the signal
        return None


def ml_signal(text: str) -> Signal | None:
    """A single cited signal carrying the model's phishing probability."""
    model = _model()
    if model is None or not text.strip():
        return None
    try:
        prob = float(model.predict_proba([text])[0][1])
    except Exception:  # noqa: BLE001
        return None
    # 0 points at/below 50%, ramping to _MAX_WEIGHT at 100%.
    weight = round(max(0.0, prob - 0.5) * 2 * _MAX_WEIGHT)
    return Signal(
        id="ml_phishing_likelihood",
        source="ML model (TF-IDF + logistic regression, offline)",
        value=f"phishing-likelihood {prob:.0%}",
        weight=weight,
    )
