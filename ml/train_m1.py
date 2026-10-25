
from pathlib import Path
import json
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix


data_file = (
    Path(__file__).parent
    / "data"
    / "Prompt_INJECTION_And_Benign_DATASET.jsonl"
)


records = []

with open(data_file, "r", encoding="utf-8") as file:
    for line in file:
        if line.strip():
            records.append(json.loads(line))

data = pd.DataFrame(records)


data = data[["prompt", "label"]].dropna()
data = data.drop_duplicates(subset=["prompt"])


data["label"] = data["label"].map({
    "benign": 0,
    "malicious": 1
})


data = data.dropna(subset=["label"])
data["label"] = data["label"].astype(int)

print("Dataset shape:", data.shape)
print("\nLabel distribution:")
print(data["label"].value_counts().rename({
    0: "benign",
    1: "malicious"
}))


X = data["prompt"]
y = data["label"]


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2)
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42
        )
    )
])


model.fit(X_train, y_train)


train_predictions = model.predict(X_train)

print("\nTraining Performance:")
print(
    classification_report(
        y_train,
        train_predictions,
        labels=[0, 1],
        target_names=["benign", "malicious"],
        zero_division=0
    )
)

predictions = model.predict(X_test)

print("\nM1 Prompt Injection Detection Results")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["benign", "malicious"],
        zero_division=0
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))


model_dir = Path(__file__).parent / "models"
model_dir.mkdir(parents=True, exist_ok=True)

model_path = model_dir / "m1_prompt_injection_model.joblib"
joblib.dump(model, model_path)

print(f"\nM1 model saved to: {model_path}")

