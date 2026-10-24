from pathlib import Path
import joblib 
import pandas as pd 
from sklearn.linear_model import LogisticRegression 
from sklearn.metrics import classification_report 
from sklearn.model_selection import train_test_split 
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import numpy as np

data_file = Path(__file__).parent / "data" / "transactions.csv"

data = pd.read_csv(data_file)

print("Dataset shape:", data.shape)
print("Available columns:", data.columns.tolist())

# Convert timestamps and sort transactions by customer and time.
data["timestamp"] = pd.to_datetime(data["timestamp"])
data = data.sort_values(["customer_id", "timestamp"])
data["hour"] = data["timestamp"].dt.hour
data["is_overnight"] = (data["hour"] < 6).astype(int)
data["amount_log"] = np.log1p(data["amount"])
data["is_large_amount"] = (data["amount"] > 1000).astype(int)

data["average_amount"] = 0.0
customer_averages = data.groupby("customer_id")["amount"].mean()
data["average_amount"] = data["customer_id"].map(customer_averages)
data["amount_vs_average"] = data["amount"] / data["average_amount"]

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

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

model = Pipeline([
    ("scaler", StandardScaler()),
    (
        "classifier",
        LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
        ),
    ),
])
model.fit(X_train, y_train)

predictions = model.predict(X_test)
print("\nM3 Logistic Regression Results")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["normal", "suspicious"],
        zero_division=0,
    )
)

model_dir = Path(__file__).parent / "models"
model_dir.mkdir(parents=True, exist_ok=True)
joblib.dump(model, model_dir / "m3_logistic_model.joblib")
print("Logistic Regression model saved successfully!")