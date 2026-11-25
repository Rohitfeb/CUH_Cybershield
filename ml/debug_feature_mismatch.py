
import pandas as pd
import re
from urllib.parse import urlparse, parse_qsl

# Read only 20 rows
data = pd.read_csv(
    "dataset/cleaned_phishing_urls.csv",
    nrows=20
)

for index, row in data.iterrows():

    url = str(row["URL"])
    parsed = urlparse(url.strip())

    # Our current token calculation
    tokens = re.findall(r"[a-zA-Z0-9]+", url.strip())

    print("\n" + "=" * 60)
    print("ROW:", index)

    print("URL:", repr(url))

    print("\nTOKEN COUNT")
    print("Dataset value:", row["token_count"])
    print("Our value:", len(tokens))
    print("Tokens:", tokens)

    print("\nQUERY PARAMETER COUNT")
    print("Dataset value:", row["query_param_count"])
    print("Our value:", len(
        parse_qsl(parsed.query, keep_blank_values=True)
    ))

    print("URL contains ?: ", url.count("?"))
    print("URL contains &: ", url.count("&"))
    print("URL contains =: ", url.count("="))
    print("Parsed query:", repr(parsed.query))
