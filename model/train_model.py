import csv
import pickle
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = BASE_DIR / "dataset" / "emails.csv"
MODEL_PATH = BASE_DIR / "model" / "model.pkl"
VECTORIZER_PATH = BASE_DIR / "model" / "vectorizer.pkl"


emails = []
labels = []


# Read dataset
with open(
    DATASET_PATH,
    newline="",
    encoding="utf-8"
) as file:

    reader = csv.DictReader(file)

    for row in reader:

        emails.append(
            row["email"]
        )

        labels.append(
            row["label"]
        )


# Convert email text into numerical features
vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    max_features=5000,
    sublinear_tf=True
)


X = vectorizer.fit_transform(
    emails
)


# Train Logistic Regression model
model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)


model.fit(
    X,
    labels
)


# Save vectorizer
with open(
    VECTORIZER_PATH,
    "wb"
) as file:

    pickle.dump(
        vectorizer,
        file
    )


# Save model
with open(
    MODEL_PATH,
    "wb"
) as file:

    pickle.dump(
        model,
        file
    )


print()
print("===================================")
print("   ML MODEL TRAINED SUCCESSFULLY")
print("===================================")
print()
print("Total emails :", len(emails))
print("Threat emails:", labels.count("threat"))
print("Safe emails  :", labels.count("safe"))
print()
print("Model saved to:")
print(MODEL_PATH)
print()
print("Vectorizer saved to:")
print(VECTORIZER_PATH)
print()