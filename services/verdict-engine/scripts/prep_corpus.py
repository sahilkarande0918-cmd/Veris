"""Build the committable training corpus from a downloaded public phishing set.

Subsamples a balanced few-thousand-row set (bodies truncated) from a large
source CSV (e.g. the zefang-liu / Kaggle phishing-email set, columns
"Email Text","Email Type") into fixtures/ml/email_corpus_full.csv. Deterministic
(seeded). The compact curated jsonl stays as the offline-swappable fixture.

Run:  .venv/Scripts/python scripts/prep_corpus.py <path-to-source.csv>
"""

import csv
import random
import sys
from pathlib import Path

csv.field_size_limit(2**31 - 1)
SRC = Path(sys.argv[1])
OUT = Path(__file__).resolve().parents[3] / "fixtures" / "ml" / "email_corpus_full.csv"
PER_CLASS = 3000
MAX_CHARS = 800


def main() -> None:
    random.seed(42)
    phish: list[str] = []
    legit: list[str] = []
    with SRC.open(encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # header
        for row in reader:
            if len(row) < 3:
                continue
            text = " ".join((row[1] or "").split())[:MAX_CHARS]
            typ = (row[2] or "").strip().lower()
            if not text or text.lower() == "empty":
                continue
            if "phish" in typ:
                phish.append(text)
            elif "safe" in typ or "ham" in typ or "legit" in typ:
                legit.append(text)

    n = min(PER_CLASS, len(phish), len(legit))
    random.shuffle(phish)
    random.shuffle(legit)
    rows = [(t, 1) for t in phish[:n]] + [(t, 0) for t in legit[:n]]
    random.shuffle(rows)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows(rows)
    print(f"wrote {len(rows)} balanced rows ({n} phishing, {n} legit) -> {OUT}")


if __name__ == "__main__":
    main()
