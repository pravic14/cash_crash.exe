"""Print precision, recall, F1, and the false-positive rate on legitimate payments."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.train_m1 import EXTRA, build_pipeline as build_m1
from ml.train_m2 import build_pipeline as build_m2


def false_positive_rate(y_true, y_pred) -> float:
    negatives = [index for index, label in enumerate(y_true) if int(label) == 0]
    if not negatives:
        return 0.0
    return sum(int(y_pred[index]) == 1 for index in negatives) / len(negatives)


def report(title: str, y_true, y_pred, names: list[str]) -> None:
    print(f"\n{title}")
    print(classification_report(y_true, y_pred, target_names=names, zero_division=0))
    print("False positive rate on the legitimate class:", round(false_positive_rate(y_true, y_pred), 3))


def main() -> None:
    root = Path(__file__).resolve().parent
    messages = []
    labels = []
    with (root / "data" / "Prompt_INJECTION_And_Benign_DATASET.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            messages.append(row["prompt"])
            labels.append(1 if row["label"] == "malicious" else 0)
    for text, label in EXTRA:
        messages.append(text)
        labels.append(label)
    injection = pd.DataFrame({"message": messages, "label": labels})
    x_train, x_test, y_train, y_test = train_test_split(
        injection["message"], injection["label"], test_size=0.2, random_state=42, stratify=injection["label"]
    )
    m1 = build_m1()
    m1.fit(x_train, y_train)
    report("M1 injection", y_test, (m1.predict_proba(x_test)[:, 1] >= 0.5).astype(int), ["benign", "injection"])

    spam = pd.read_csv(root / "data" / "spam.csv", encoding="latin-1")[["v1", "v2"]]
    spam.columns = ["label", "message"]
    spam["label"] = spam["label"].map({"ham": 0, "spam": 1})
    uk = pd.read_csv(root / "data" / "uk_messages.csv")
    uk["label"] = uk["label"].map({"ham": 0, "scam": 1})
    uk["weight"] = uk["label"].map({1: 8.0, 0: 4.0})
    scam = pd.concat([spam.assign(weight=1.0), uk], ignore_index=True).dropna()
    x_train, x_test, y_train, y_test, w_train, _w_test = train_test_split(
        scam["message"], scam["label"], scam["weight"], test_size=0.2, random_state=42, stratify=scam["label"]
    )
    m2 = build_m2()
    m2.fit(x_train, y_train, classifier__sample_weight=w_train)
    report("M2 scam language", y_test, (m2.predict_proba(x_test)[:, 1] >= 0.5).astype(int), ["genuine", "scam"])

    saved = joblib.load(root / "models" / "m3_anomaly_model.joblib")
    print("\nM3 saved customers:", ", ".join(sorted(saved["customers"])))
    print("txn_risk is the percentile versus that customer's normal history. 0.9 means rarer than 90% of it.")


if __name__ == "__main__":
    main()
