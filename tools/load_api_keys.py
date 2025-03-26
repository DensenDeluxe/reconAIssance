import os
import re

API_KEYS_PATH = os.path.join(os.path.dirname(__file__), "..", "api_keys.txt")

def load_keys():
    keys = {}
    if os.path.exists(API_KEYS_PATH):
        with open(API_KEYS_PATH) as f:
            for line in f:
                match = re.match(r'(\w+)_api_key\s*=\s*["\'](.+?)["\']', line.strip())
                if match:
                    keys[match.group(1)] = match.group(2)
    return keys

