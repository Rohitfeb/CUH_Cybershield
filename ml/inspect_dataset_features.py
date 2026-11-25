
import pandas as pd
import re
import random
from urllib.parse import urlparse, parse_qsl
from collections import Counter

print("Starting memory-efficient dataset inspection...")

file_path = "dataset/cleaned_phishing_urls.csv"

query_distribution = Counter()
token_distribution = Counter()

sample_records = []

# Read only the three required columns in batches
reader = pd.read_csv(
    file_path,
    usecols=["URL", "token_count", "query_param_count"],
    dtype={
        "URL": "string",
        "token_count": "int32",
        "query_param_count": "int32"
    },
    chunksize=5000,
    engine="python"
)

for chunk_number, chunk in enumerate(reader, start=1):

    query_distribution.update(
        chunk["query_param_count"].value_counts().to_dict()
    )

    token_distribution.update(
        chunk["token_count"].value_counts().to_dict()
    )

    # Keep only the first 15 records for inspection
    if len(sample_records) < 15:
        remaining = 15 - len(sample_records)

        records = chunk.head(remaining)

        for _, row in records.iterrows():
            sample_records.append(row)

    print(f"Processed batch {chunk_number}")

print("\n1. QUERY PARAMETER COUNT DISTRIBUTION")

for value, count in sorted(query_distribution.items()):
    print(f"Value {value}: {count} records")

print("\n2. TOKEN COUNT DISTRIBUTION")

for value, count in sorted(token_distribution.items()):
    print(f"Value {value}: {count} records")

print("\n3. SAMPLE URL COMPARISON")

for row in sample_records:

    url = str(row["URL"]).strip()

    parsed = urlparse(url)

    tokens = re.findall(r"[a-zA-Z0-9]+", url)

    actual_query_count = len(
        parse_qsl(parsed.query, keep_blank_values=True)
    )

    print("\nURL:", url)

    print("Dataset token count:", row["token_count"])
    print("Our token count:", len(tokens))

    print("Dataset query count:", row["query_param_count"])
    print("Actual query count:", actual_query_count)

print("\nDataset inspection completed successfully!")
