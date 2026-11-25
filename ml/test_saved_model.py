
import os

# Limit memory-intensive numerical library threads
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

import joblib
import pandas as pd
from threadpoolctl import threadpool_limits

print("Starting model test...", flush=True)

try:
    with threadpool_limits(limits=1):

        # Step 1: Load saved model
        saved_data = joblib.load("models/url_detector.pkl")

        model = saved_data["model"]
        features = saved_data["features"]

        print("Model loaded successfully!", flush=True)

        # Step 2: Read only ONE row and required columns
        sample = pd.read_csv(
            "dataset/cleaned_phishing_urls.csv",
            usecols=features,
            nrows=1
        )

        print("One sample loaded successfully!", flush=True)

        # Step 3: Prepare features
        X_sample = sample[features].astype("float32")

        # Step 4: Predict
        prediction = model.predict(X_sample)[0]

        labels = {
            0: "LEGITIMATE",
            1: "PHISHING"
        }

        # Step 5: Display result
        print("\nModel prediction:")
        print(labels[prediction])

        print("\nModel testing completed successfully!")

except Exception as e:
    print("\nError occurred:", repr(e))
