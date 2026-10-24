from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

import numpy as np

data_file = Path(__file__).parent / "data" / "transactions.csv"

data = pd.read_csv(data_file)

print("Dataset shape:", data.shape)
print("Available columns:", data.columns.tolist())

data["timestamp"] = pd.to_datetime(data["timestamp"])

data = data.sort_values(["customer_id", "timestamp"])

data["hour"] = data["timestamp"].dt.hour

data["is_overnight"] = ( (data["hour"] < 6) ).astype(int)

data["amount_log"] = np.log1p(data["amount"])

data["is_large_amount"] = ( data["amount"] > 1000 ).astype(int)

data["average_amount"] = 0.0

customer_averages = data.groupby("customer_id")["amount"].mean()

data["average_amount"] = data["customer_id"].map(customer_averages)

# Compare each payment with the customer's average
data["amount_vs_average"] = (
    data["amount"] / data["average_amount"]
)


features = [
    "amount",
    "is_new_payee",
    "hour",
    "is_overnight",
    "is_large_amount",
    "average_amount",
    "amount_vs_average",
]
X = data[features]
y = data["scenario_label"].map({
    "normal": 0,
    "suspicious": 1,
})

print("\nAverage transaction amount by scenario:")
print(data.groupby("scenario_label")["amount"].describe())

print("\nNew payee frequency by scenario:")
print(
    data.groupby("scenario_label")["is_new_payee"]
    .value_counts(normalize=True)
)


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.3,
    random_state=42,
    stratify=y,
)



scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)



model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42,
)

model.fit(X_train_scaled)
predictions = model.predict(X_test_scaled)
predictions = (predictions == -1).astype(int)

print("\nM3 Baseline Results")

print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["normal", "suspicious"],
        zero_division=0,
    )
)


# Save them mods babes
model_dir = Path(__file__).parent / "models"
model_dir.mkdir(parents=True, exist_ok=True)

joblib.dump(model, model_dir / "m3_anomaly_model.joblib")
joblib.dump(scaler, model_dir / "m3_scaler.joblib")

print("\nM3 model and scaler saved successfully!") 