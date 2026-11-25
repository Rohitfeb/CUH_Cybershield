
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from utils.url_detector import extract_url_features

# Load only one dataset row
data = pd.read_csv(
    "dataset/cleaned_phishing_urls.csv",
    nrows=1
)

# Get original URL
url = data.loc[0, "URL"]

print("Original URL:")
print(url)

# Original feature values
original = data.iloc[0]

# Calculate features again
calculated = extract_url_features(url)

print("\nFEATURE COMPARISON")
print("-" * 60)

mismatches = 0

for feature, calculated_value in calculated.items():

    original_value = float(original[feature])

    difference = abs(original_value - calculated_value)

    matched = difference < 0.0001

    print(f"\nFeature: {feature}")
    print("Dataset value:", original_value)
    print("Calculated value:", calculated_value)
    print("Status:", "MATCH" if matched else "MISMATCH")

    if not matched:
        mismatches += 1

print("\nTotal features:", len(calculated))
print("Mismatched features:", mismatches)

if mismatches == 0:
    print("\nAll features match successfully!")
else:
    print("\nSome feature calculations need correction.")
