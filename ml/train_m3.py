"""M3 transaction anomaly.

One IsolationForest per customer, fit on that customer's normal history only.
The score is txn_risk in 0..1: how unusual the payment is versus that habit.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler

try:
    from features import FEATURE_NAMES, featurize
except ImportError:
    from ml.features import FEATURE_NAMES, featurize

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "transactions.csv"
MODEL = ROOT / "models" / "m3_anomaly_model.joblib"


def load_frame() -> pd.DataFrame:
    frame = pd.read_csv(DATA)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    return frame.sort_values(["customer_id", "timestamp"])


def balances(frame: pd.DataFrame) -> dict[str, float]:
    try:
        from gen_transactions import CUSTOMER_PROFILES
    except ImportError:
        from ml.gen_transactions import CUSTOMER_PROFILES

    return {
        customer: float(CUSTOMER_PROFILES[customer]["balance"])
        for customer in frame["customer_id"].unique()
    }


def build_examples(frame: pd.DataFrame) -> pd.DataFrame:
    known = balances(frame)
    rows = []
    for customer, group in frame.groupby("customer_id", sort=False):
        habit: list[dict] = []
        balance = known[customer]
        for record in group.to_dict(orient="records"):
            features = featurize(habit, record, balance)
            features["customer_id"] = customer
            features["label"] = 1 if record["scenario_label"] == "suspicious" else 0
            rows.append(features)
            if record["scenario_label"] == "normal":
                habit.append(record)
    return pd.DataFrame(rows)


def fit_customer(normal_rows: np.ndarray) -> tuple[IsolationForest, StandardScaler, np.ndarray]:
    scaler = StandardScaler()
    scaled = scaler.fit_transform(normal_rows)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(scaled)
    raw = -model.decision_function(scaled)
    return model, scaler, np.sort(raw)


def risk_from_raw(raw: float, normal_raw: np.ndarray) -> float:
    if len(normal_raw) == 0:
        return 0.0
    return float(np.mean(normal_raw <= raw))


def main() -> None:
    examples = build_examples(load_frame())
    bundle: dict = {"customers": {}, "features": FEATURE_NAMES}
    y_true = []
    y_pred = []
    for customer, group in examples.groupby("customer_id"):
        normal = group[group["label"] == 0]
        suspicious = group[group["label"] == 1]

        train_normal = normal.sample(frac=0.7, random_state=42)
        test_normal = normal.drop(train_normal.index)
        model, scaler, normal_raw = fit_customer(train_normal[FEATURE_NAMES].to_numpy(dtype=float))

        bundle["customers"][customer] = {
            "model": model,
            "scaler": scaler,
            "normal_raw": normal_raw,
        }

        held = pd.concat([test_normal, suspicious], ignore_index=True)
        scaled = scaler.transform(held[FEATURE_NAMES].to_numpy(dtype=float))
        raw = -model.decision_function(scaled)
        risks = np.array([risk_from_raw(value, normal_raw) for value in raw])
        predictions = (risks >= 0.9).astype(int)
        y_true.extend(held["label"].tolist())
        y_pred.extend(predictions.tolist())

    print(classification_report(y_true, y_pred, target_names=["normal", "suspicious"], zero_division=0))
    negatives = [index for index, label in enumerate(y_true) if label == 0]
    fpr = sum(y_pred[index] == 1 for index in negatives) / len(negatives)
    print("False positive rate on normal payments at txn_risk >= 0.9:", round(fpr, 3))
    MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL)
    print("Model saved to:", MODEL)


if __name__ == "__main__":
    main()
