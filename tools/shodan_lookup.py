import os
import sys
import json
import hashlib
import logging
import requests
from pathlib import Path
from llm_wrapper import use_llm
from load_api_keys import load_keys

logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    fh = logging.FileHandler("recon_log.txt", mode="a")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)

SHODAN_DB = Path("loot/shodan_db.jsonl")
QUERY_CACHE = Path("loot/shodan_query_cache.json")
API_SEARCH = "https://api.shodan.io/shodan/host/search"
API_HOST = "https://api.shodan.io/shodan/host/"


def hash_query(query):
    return hashlib.sha1(query.encode()).hexdigest()


def load_query_cache():
    if QUERY_CACHE.exists():
        return json.load(open(QUERY_CACHE))
    return {}


def save_query_cache(cache):
    with open(QUERY_CACHE, "w") as f:
        json.dump(cache, f, indent=2)


def shodan_search(query, key, max_results=20):
    cache = load_query_cache()
    query_hash = hash_query(query)

    if query_hash in cache:
        logger.info(f"[↩] Using cached query result for: {query}")
        return cache[query_hash]["ips"]

    logger.info(f"[🌐] Performing new Shodan query: {query}")
    r = requests.get(API_SEARCH, params={"key": key, "query": query})
    if r.status_code != 200:
        logger.warning(f"Shodan query failed: {r.status_code}")
        return []

    matches = r.json().get("matches", [])[:max_results]
    ips = [m["ip_str"] for m in matches if "ip_str" in m]
    cache[query_hash] = {"query": query, "ips": ips, "timestamp": str(Path().stat().st_mtime)}
    save_query_cache(cache)
    return ips


def enrich_host(ip, key):
    r = requests.get(f"{API_HOST}{ip}?key={key}")
    if r.status_code != 200:
        logger.warning(f"Failed to get host data for {ip}")
        return None
    return r.json()


def store_in_db(data):
    with open(SHODAN_DB, "a") as db:
        db.write(json.dumps(data) + "\n")


def already_in_db(ip):
    if not SHODAN_DB.exists():
        return False
    with open(SHODAN_DB) as db:
        for line in db:
            if f'"ip_str": "{ip}"' in line:
                return True
    return False


def run():
    user_input = input("Where to reconAIssance? : ").strip()
    prompt = f"""You are a recon assistant. Given the input, suggest a Shodan query.
Input: {user_input}
ONLY RETURN JSON like:
{{ "query": "...", "description": "..." }}"""

    result = use_llm("intel_prompt_query", prompt)
    try:
        parsed = json.loads(result.strip().split("\n")[-1])
        query = parsed.get("query", "")
        desc = parsed.get("description", "")
    except Exception as e:
        logger.error("Failed to parse LLM response")
        return

    print(f"🔍 {desc}\n🔎 {query}")
    key = load_keys().get("shodan")
    if not key:
        logger.error("No Shodan API key.")
        return

    ips = shodan_search(query, key)
    print(f"Found {len(ips)} IPs")

    for ip in ips:
        if already_in_db(ip):
            logger.debug(f"Skipping {ip} – already in DB")
            continue
        host_data = enrich_host(ip, key)
        if host_data:
            store_in_db(host_data)
            logger.info(f"Stored {ip} to DB")

if __name__ == "__main__":
    run()
