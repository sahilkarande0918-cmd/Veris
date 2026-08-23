"""Train the email phishing classifier [SIH26106, Decision 1].

A tiny, fully-offline TF-IDF + Logistic Regression model on the bundled curated
corpus (fixtures/ml/email_corpus.jsonl -- swap in Nazario/Kaggle for production).
Its output is ONE cited, weighted signal (ml_phishing_likelihood) that feeds the
score; hard signals (auth fail, spoof, blocklist) always dominate. The trained
model is committed to app/models/ so the engine runs offline with no training.

Run:  .venv/Scripts/python scripts/train_email_classifier.py
"""

import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "fixtures" / "ml" / "email_corpus.jsonl"
OUT = Path(__file__).resolve().parents[1] / "app" / "models" / "email_clf.joblib"


def main() -> None:
    rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]
    texts = [r["text"] for r in rows]
    labels = [r["label"] for r in rows]

    pipe = Pipeline(
        [
            ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ]
    )
    scores = cross_val_score(pipe, texts, labels, cv=5, scoring="accuracy")
    print(f"5-fold CV accuracy: {scores.mean():.2%} (+/- {scores.std():.2%}) on {len(rows)} samples")

    pipe.fit(texts, labels)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, OUT)
    print(f"saved model -> {OUT}")


if __name__ == "__main__":
    main()
