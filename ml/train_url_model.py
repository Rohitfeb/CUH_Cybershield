
import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# 1. Load cleaned dataset
data = pd.read_csv("dataset/cleaned_phishing_urls.csv")

print("Dataset loaded successfully!")
print("Dataset shape:", data.shape)

# 2. Select URL features
features = [
    "url_length",
    "has_ip_address",
    "dot_count",
    "https_flag",
    "url_entropy",
    "subdomain_count",
    "tld_length",
    "path_length",
    "has_hyphen_in_domain",
    "number_of_digits",
    "tld_popularity",
    "suspicious_file_extension",
    "domain_name_length",
    "percentage_numeric_chars"
]

# 3. Prepare input features
# Convert feature columns into numeric values
X = data[features].apply(
    pd.to_numeric, errors="coerce"
).astype("float32")

# 4. Prepare target labels
# Original: 0 = Phishing, 1 = Legitimate
# New:      1 = Phishing, 0 = Legitimate

y = (data["ClassLabel"] == 0).astype(int)

# 5. Remove any invalid feature rows
valid_rows = X.notna().all(axis=1)

X = X.loc[valid_rows]
y = y.loc[valid_rows]

print("\nFeature shape:", X.shape)
print("\nTarget distribution:")
print(y.value_counts())

# 6. Split dataset into training and testing
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining records:", len(X_train))
print("Testing records:", len(X_test))

# 7. Create Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_leaf=2,
    max_features="sqrt",
    random_state=42,
    class_weight="balanced",
    n_jobs=1
)

# 8. Train model
print("\nTraining Random Forest model...")
model.fit(X_train, y_train)

print("Model training completed!")

# 9. Make predictions
y_pred = model.predict(X_test)

# 10. Evaluate model
print("\n========== MODEL EVALUATION ==========")

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall:", recall_score(y_test, y_pred))
print("F1 Score:", f1_score(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    target_names=["Legitimate", "Phishing"]
))

# 11. Display important features
importance = pd.Series(
    model.feature_importances_,
    index=features
).sort_values(ascending=False)

print("\nTop 10 Important Features:")
print(importance.head(10))

# 12. Save trained model
os.makedirs("models", exist_ok=True)

joblib.dump(
    {
        "model": model,
        "features": features,
        "label_mapping": {
            0: "Legitimate",
            1: "Phishing"
        }
    },
    "models/url_detector.pkl"
)

print("\nModel saved successfully!")
print("Location: models/url_detector.pkl")
