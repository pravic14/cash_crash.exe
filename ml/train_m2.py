
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


data_file = Path(__file__).parent / "data" / "spam.csv"

data = pd.read_csv(data_file, encoding="latin-1")
data = data[["v1", "v2"]]
data.columns = ["label", "message"]

data = data.dropna().drop_duplicates()
data["label"] = data["label"].map({"ham": 0, "spam": 1})


# Split the data into training and testing sets
x_train, x_test, y_train, y_test = train_test_split(
    data["message"],
    data["label"],
    test_size=0.2,
    random_state=42,
    stratify=data["label"],
)


# Create and train the model
model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
    ("classifier", LogisticRegression(max_iter=1000)),
])

model.fit(x_train, y_train)


# Evaluate the model
spam_scores = model.predict_proba(x_test)[:, 1]
predictions = (spam_scores >= 0.2).astype(int)

print("Accuracy:", round(accuracy_score(y_test, predictions), 3))
print(classification_report(
    y_test,
    predictions,
    target_names=["ham", "spam"],
    zero_division=0,
))


# Save the trained model
model_file = Path(__file__).parent / "models" / "m2_spam_model.joblib"
model_file.parent.mkdir(parents=True, exist_ok=True)

joblib.dump(model, model_file)

print("Model saved to:", model_file)
