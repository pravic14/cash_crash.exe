"""M2 scam-language detector.

UCI SMS spam plus UK scam and genuine bank lines. Same TF-IDF pipeline as M1.
Saves p(scam). Top n-grams are read back at inference time.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parent
SPAM = ROOT / "data" / "spam.csv"
UK = ROOT / "data" / "uk_messages.csv"
MODEL = ROOT / "models" / "m2_scam_model.joblib"


def load_rows() -> pd.DataFrame:
    spam = pd.read_csv(SPAM, encoding="latin-1")[["v1", "v2"]]
    spam.columns = ["label", "message"]
    spam["label"] = spam["label"].map({"ham": 0, "spam": 1})
    spam["weight"] = 1.0
    uk = pd.read_csv(UK)
    uk["label"] = uk["label"].map({"ham": 0, "scam": 1})
    uk["weight"] = uk["label"].map({1: 25.0, 0: 12.0})
    data = pd.concat([spam, uk], ignore_index=True)
    return data.dropna(subset=["message", "label"]).drop_duplicates(subset=["message"])


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1)),
                        (
                            "char",
                            TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2),
                        ),
                    ]
                ),
            ),
            (
                "classifier",
                LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42),
            ),
        ]
    )


def false_positive_rate(y_true, y_pred) -> float:
    negatives = [index for index, label in enumerate(y_true) if label == 0]
    if not negatives:
        return 0.0
    return sum(y_pred[index] == 1 for index in negatives) / len(negatives)


def main() -> None:
    data = load_rows()
    x_train, x_test, y_train, y_test, w_train, _w_test = train_test_split(
        data["message"],
        data["label"],
        data["weight"],
        test_size=0.2,
        random_state=42,
        stratify=data["label"],
    )
    model = build_pipeline()
    model.fit(x_train, y_train, classifier__sample_weight=w_train)
    scores = model.predict_proba(x_test)[:, 1]
    predictions = (scores >= 0.5).astype(int)
    print(classification_report(y_test, predictions, target_names=["genuine", "scam"], zero_division=0))
    print("False positive rate on genuine text:", round(false_positive_rate(list(y_test), predictions), 3))
    MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL)
    print("Model saved to:", MODEL)


if __name__ == "__main__":
    main()
