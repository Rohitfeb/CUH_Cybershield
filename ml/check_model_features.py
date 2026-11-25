
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Limit numerical library threads
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import joblib
import pandas as pd

from utils.url_detector import extract_url_features

print("Loading saved URL detection model...")

saved_data = joblib.load("models/url_detector.pkl")

model = saved_data["model"]
features = saved_data["features"]
label_mapping = saved_data["label_mapping"]

print("Model loaded successfully!")
print("Expected features:", len(features))

# Test URL (analyze the text only; do not open it)
test_url = "https://www.google.com/search?q=python"

url_features = extract_url_features(test_url)

# Compare feature names
missing = [f for f in features if f not in url_features]
extra = [f for f in url_features if f not in features]

print("\nMissing features:", missing)
print("Extra features:", extra)

if missing or extra:
    print("\nFEATURE MISMATCH FOUND!")
else:
    print("\nAll feature names match!")

    input_data = pd.DataFrame(
        [[url_features[f] for f in features]],
        columns=features
    )

    prediction = int(model.predict(input_data)[0])

    print("\nURL:", test_url)
    print("Prediction:", label_mapping[prediction])

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(input_data)[0]
        print("\nPrediction probabilities:")

        for class_value, probability in zip(
            model.classes_, probabilities
        ):
            print(
                label_mapping[int(class_value)],
                ":", round(float(probability) * 100, 2), "%"
            )
