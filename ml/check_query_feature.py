
import pandas as pd

file_path = "dataset/cleaned_phishing_urls.csv"

reader = pd.read_csv(
    file_path,
    usecols=["URL", "query_param_count"],
    chunksize=5000,
    engine="python"
)

checked = 0

print("Checking query parameter feature...\n")

for chunk in reader:

    # Find URLs without query symbols
    no_query = chunk[
        ~chunk["URL"].astype(str).str.contains(
            r"[?&=]", regex=True
        )
    ]

    # Find records where dataset count is greater than zero
    suspicious = no_query[
        no_query["query_param_count"] > 0
    ]

    for _, row in suspicious.head(5).iterrows():

        print("URL:", row["URL"])
        print("Dataset query count:", row["query_param_count"])
        print("-" * 45)

        checked += 1

        if checked >= 20:
            break

    if checked >= 20:
        break

print("\nTotal suspicious examples displayed:", checked)
