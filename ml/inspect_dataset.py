
import pandas as pd

# Load dataset
data = pd.read_csv("dataset/phishing_urls.csv")

print("Dataset loaded successfully!")

# Display first 5 records
print("\nFirst 5 rows:")
print(data.head())

# Display column names
print("\nColumn names:")
print(data.columns.tolist())

# Display dataset size
print("\nDataset shape:")
print(data.shape)

# Check missing values
print("\nMissing values:")
print(data.isnull().sum())

# Check class distribution
print("\nLabel distribution:")
if "ClassLabel" in data.columns:
    print(data["ClassLabel"].value_counts())
else:
    print("ClassLabel column not found!")
