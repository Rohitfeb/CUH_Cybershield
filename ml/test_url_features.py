
import sys
from pathlib import Path

# Add the main project directory to Python's import path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from utils.url_detector import extract_url_features

test_url = "https://www.google.com/search?q=python"

features = extract_url_features(test_url)

print("URL:", test_url)

print("\nExtracted URL Features:")

for name, value in features.items():
    print(f"{name}: {value}")

print("\nTotal features:", len(features))
