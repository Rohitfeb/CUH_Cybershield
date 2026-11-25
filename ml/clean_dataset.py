
import pandas as pd

# Load original dataset
data = pd.read_csv("dataset/phishing_urls.csv")

print("Original dataset shape:", data.shape)

# Step 1: Remove records with missing labels
data = data.dropna(subset=["ClassLabel"])

# Step 2: Remove records with empty URLs
data = data.dropna(subset=["URL"])
data = data[data["URL"].astype(str).str.strip() != ""]

# Step 3: Remove exact duplicate records
data = data.drop_duplicates()

# Step 4: Convert labels into integers
data["ClassLabel"] = data["ClassLabel"].astype(int)

# Step 5: Display cleaned dataset information
print("\nCleaned dataset shape:", data.shape)

print("\nMissing values:")
print(data.isnull().sum())

print("\nLabel distribution:")
print(data["ClassLabel"].value_counts())

# Step 6: Save cleaned dataset
data.to_csv("dataset/cleaned_phishing_urls.csv", index=False)

print("\nCleaned dataset saved successfully!")
