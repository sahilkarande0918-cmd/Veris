"""Train the email phishing classifier [SIH26106, Decision 1].

TF-IDF + Logistic Regression, fully offline. Trains on the larger corpus
(fixtures/ml/email_corpus_full.csv, a balanced few-thousand-row public sample;
rebuild it with prep_corpus.py) and reports honest held-out metrics; falls back
to the compact curated jsonl if the CSV is absent. Its output is ONE cited,
weighted signal (ml_phishing_likelihood) that feeds the score; hard signals
always dominate. The trained model is committed to app/models/.

Run:  .venv/Scripts/python scripts/train_email_classifier.py
"""

import csv
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

csv.field_size_limit(2**31 - 1)
ROOT = Path(__file__).resolve().parents[3]
FULL = ROOT / "fixtures" / "ml" / "email_corpus_full.csv"
COMPACT = ROOT / "fixtures" / "ml" / "email_corpus.jsonl"
OUT = Path(__file__).resolve().parents[1] / "app" / "models" / "email_clf.joblib"


def _load() -> tuple[list[str], list[int], str]:
    if FULL.exists():
        with FULL.open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        return [r["text"] for r in rows], [int(r["label"]) for r in rows], FULL.name
    rows = [json.loads(l) for l in COMPACT.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [r["text"] for r in rows], [r["label"] for r in rows], COMPACT.name


def main() -> None:
    texts, labels, src = _load()
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    pipe = Pipeline(
        [
            ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words="english")),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
        ]
    )
    pipe.fit(X_train, y_train)

    print(f"source: {src}  |  train={len(X_train)}  test={len(X_test)}")
    print(classification_report(y_test, pipe.predict(X_test), target_names=["legit", "phishing"], digits=3))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, OUT)
    print(f"saved model -> {OUT}")


if __name__ == "__main__":
    main()
