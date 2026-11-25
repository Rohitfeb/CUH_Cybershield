
import pandas as pd

# Load cleaned dataset
data = pd.read_csv("dataset/cleaned_phishing_urls.csv")

print("Dataset columns and data types:")
print(data.dtypes)

print("\nFirst 5 feature records:")
print(data.head())

print("\nUnique values in ClassLabel:")
print(data["ClassLabel"].unique())

print("\nUnique values in tld_popularity:")
print(data["tld_popularity"].unique()[:10])
