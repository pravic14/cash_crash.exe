"""M4 risk fusion.

Small logistic regression over the scores the other guards publish:
text_risk, txn_risk, rag_sim, urgency, and authority. Prints the weights.
Saves final_risk and the LOW / MEDIUM / HIGH cut points.
"""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.features import FEATURE_NAMES, as_row, calm_repeat, featurize
from ml.gen_transactions import CUSTOMER_PROFILES
from ml.train_m3 import risk_from_raw
from rag.corpus import normalise
from rag.retriever import _pattern_hits

DATA = Path(__file__).resolve().parent / "data" / "transactions.csv"
M1_PATH = Path(__file__).resolve().parent / "models" / "m1_injection_model.joblib"
M2_PATH = Path(__file__).resolve().parent / "models" / "m2_scam_model.joblib"
M3_PATH = Path(__file__).resolve().parent / "models" / "m3_anomaly_model.joblib"
MODEL = Path(__file__).resolve().parent / "models" / "m4_fusion_model.joblib"
FUSION_FEATURES = [
    "injection_p",
    "scam_p",
    "txn_risk",
    "rag_sim",
    "urgency_claimed",
    "claims_authority",
]
LOW_CUT = 0.33
HIGH_CUT = 0.66


def phrase_rag_sim(text: str) -> float:
    hits = _pattern_hits(normalise(text).lower())
    if not hits:
        return 0.0
    return max(hit.score for hit in hits)


def text_risk(injection_p: float, scam_p: float, rag_sim: float) -> float:
    """A weak score does not become the text risk. A strong one does."""

    parts = [rag_sim]
    if injection_p >= 0.5:
        parts.append(injection_p)
    if scam_p >= 0.5:
        parts.append(scam_p)
    return max(0.0, min(1.0, max(parts)))


def flags(text: str) -> tuple[int, int]:
    hay = text.lower()
    urgency = int(any(word in hay for word in ("urgent", "immediately", "safe account", "arrest")))
    authority = int(any(word in hay for word in ("hmrc", "police", "fraud team", "your bank")))
    return urgency, authority


def txn_risk_for(bundle: dict, customer: str, features: dict) -> float:
    slot = bundle["customers"].get(customer)
    if slot is None:
        return 0.0
    scaled = slot["scaler"].transform(np.array([as_row(features)], dtype=float))
    raw = float(-slot["model"].decision_function(scaled)[0])
    return calm_repeat(risk_from_raw(raw, slot["normal_raw"]), features)


def build_frame() -> pd.DataFrame:
    m1 = joblib.load(M1_PATH)
    m2 = joblib.load(M2_PATH)
    m3 = joblib.load(M3_PATH)
    frame = pd.read_csv(DATA)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    frame = frame.sort_values(["customer_id", "timestamp"])
    rows = []
    for customer, group in frame.groupby("customer_id", sort=False):
        habit: list[dict] = []
        balance = float(CUSTOMER_PROFILES[customer]["balance"])
        texts = group["message"].fillna(group["reference"]).astype(str).tolist()
        injection = m1.predict_proba(texts)[:, 1]
        scam = m2.predict_proba(texts)[:, 1]
        for record, injection_p, scam_p in zip(group.to_dict(orient="records"), injection, scam):
            message = str(record.get("message") or record.get("reference") or "")
            rag_sim = phrase_rag_sim(message)
            urgency, authority = flags(message)
            features = featurize(habit, record, balance)
            rows.append(
                {
                    "injection_p": float(injection_p),
                    "scam_p": float(scam_p),
                    "txn_risk": txn_risk_for(m3, customer, features),
                    "rag_sim": rag_sim,
                    "urgency_claimed": urgency,
                    "claims_authority": authority,
                    "label": 1 if record["scenario_label"] == "suspicious" else 0,
                }
            )
            if record["scenario_label"] == "normal":
                habit.append(record)
    return pd.DataFrame(rows)


def main() -> None:
    data = build_frame()
    x_train, x_test, y_train, y_test = train_test_split(
        data[FUSION_FEATURES],
        data["label"],
        test_size=0.25,
        random_state=42,
        stratify=data["label"],
    )
    model = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)
    model.fit(x_train, y_train)
    scores = model.predict_proba(x_test)[:, 1]
    predictions = (scores >= 0.5).astype(int)
    print(classification_report(y_test, predictions, target_names=["normal", "suspicious"], zero_division=0))
    negatives = np.array(y_test) == 0
    fpr = float(np.mean(predictions[negatives] == 1)) if negatives.any() else 0.0
    print("False positive rate on normal payments:", round(fpr, 3))
    print("Weights:")
    for name, weight in zip(FUSION_FEATURES, model.coef_[0]):
        print(f"  {name}: {weight:.3f}")
    MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "features": FUSION_FEATURES, "low": LOW_CUT, "high": HIGH_CUT}, MODEL)
    print("Model saved to:", MODEL)


if __name__ == "__main__":
    main()
