
import re
import math
import ipaddress
from collections import Counter
from urllib.parse import urlparse, parse_qsl


POPULAR_TLDS = {
    "com", "org", "net", "edu", "gov",
    "mil", "int", "in", "uk", "us",
    "co", "io", "ai", "de", "au"
}

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk",
    "com.au", "net.au", "co.in",
    "com.br", "co.jp"
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".zip", ".scr", ".apk",
    ".bat", ".cmd", ".msi", ".jar"
}


def get_domain_parts(hostname):

    parts = hostname.lower().strip(".").split(".")

    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        suffix = ".".join(parts[-2:])
        domain = parts[-3]
        subdomain = ".".join(parts[:-3])

    elif len(parts) >= 2:
        suffix = parts[-1]
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])

    else:
        suffix = ""
        domain = parts[0]
        subdomain = ""

    return domain, suffix, subdomain


def extract_url_features(url):

    url = url.strip()

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if not hostname:
        raise ValueError("Please enter a valid URL.")

    domain, suffix, subdomain = get_domain_parts(hostname)

    # 1. URL length
    url_length = len(url)

    # 2. IP address
    try:
        ipaddress.ip_address(hostname)
        has_ip_address = 1
    except ValueError:
        has_ip_address = 0

    # 3. Dot count
    dot_count = url.count(".")

    # 4. HTTPS flag
    https_flag = int(parsed.scheme.lower() == "https")

    # 5. URL entropy
    counts = Counter(url)

    url_entropy = -sum(
        (count / len(url)) * math.log2(count / len(url))
        for count in counts.values()
    )

    # 6. Token count
    token_count = len(re.findall(r"[a-zA-Z0-9]+", url))

    # 7. Subdomain count
    subdomain_count = (
        len(subdomain.split(".")) if subdomain else 0
    )

    # 8. Query parameter count
    query_param_count = len(
        parse_qsl(parsed.query, keep_blank_values=True)
    )

    # 9. TLD length
    tld_length = len(suffix.split(".")[-1]) if suffix else 0

    # 10. Path length
    path_length = len(parsed.path)

    # 11. Hyphen in domain
    has_hyphen_in_domain = int("-" in hostname)

    # 12. Number of digits
    number_of_digits = sum(c.isdigit() for c in url)

    # 13. TLD popularity
    tld_popularity = int(suffix.split(".")[-1] in POPULAR_TLDS)

    # 14. Suspicious file extension
    suspicious_file_extension = int(
        parsed.path.lower().endswith(tuple(SUSPICIOUS_EXTENSIONS))
    )

    # 15. Domain name length
    domain_name_length = len(domain)

    # 16. Numeric character percentage
    percentage_numeric_chars = (
        number_of_digits / len(url) * 100
    )

    return {
        "url_length": url_length,
        "has_ip_address": has_ip_address,
        "dot_count": dot_count,
        "https_flag": https_flag,
        "url_entropy": url_entropy,
        "subdomain_count": subdomain_count,
        "tld_length": tld_length,
        "path_length": path_length,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "number_of_digits": number_of_digits,
        "tld_popularity": tld_popularity,
        "suspicious_file_extension": suspicious_file_extension,
        "domain_name_length": domain_name_length,
        "percentage_numeric_chars": percentage_numeric_chars
    }
