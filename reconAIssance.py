import os
import sys
import json
import logging
import hashlib
import requests
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
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

API_SEARCH = "https://api.shodan.io/shodan/host/search"
API_HOST = "https://api.shodan.io/shodan/host/"
QUERY_CACHE = Path("loot/shodan_query_cache.json")
DB_PATH = Path("loot/shodan_db.jsonl")

def hash_query(q):
    return hashlib.sha1(q.encode()).hexdigest()

def load_query_cache():
    if QUERY_CACHE.exists():
        return json.load(open(QUERY_CACHE))
    return {}

def save_query_cache(cache):
    with open(QUERY_CACHE, "w") as f:
        json.dump(cache, f, indent=2)

def already_in_db(ip):
    if not DB_PATH.exists():
        return False
    with open(DB_PATH) as f:
        for line in f:
            if f"\"ip_str\": \"{ip}\"" in line:
                return True
    return False

def append_to_db(entry):
    with open(DB_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

def detect_language(text):
    prompt = f"""Detect the language of this text. Return ISO code only.
Text: \"{text}\"
Respond ONLY with: en, de, fr, es"""
    try:
        result = use_llm("lang_detect", prompt).strip().lower()[:2]
        if result not in ["en", "de", "fr", "es"]:
            logger.warning(f"LLM returned unsupported language: {result}")
            return "en"
        return result
    except Exception as e:
        logger.warning(f"Language detection failed: {e}")
        return "en"

def query_shodan(user_input):
    prompt = f"""You are a cybersecurity assistant.
Given a reconnaissance objective, generate a valid Shodan API query using real filters like: port:, org:, city:, title:, product:, os:, etc.

❗ Do NOT return vague phrases like \"router in France\".
Return a valid Shodan query string that will return results via the API.

Respond ONLY with valid JSON. Format:
{{"query": "...", "description": "..."}}

Input: {user_input}
"""

    try:
        result = use_llm("shodan_query_gen", prompt)
        raw = result.strip().split("\n")[-1]
        logger.debug(f"LLM raw result: {raw}")

        # Fix: replace single quotes with double quotes for JSON parsing
        if raw.startswith("{") and "'" in raw and '\"' not in raw:
            logger.warning("LLM returned JSON with single quotes – attempting auto-fix")
            raw = raw.replace("'", '"')

        if not raw.startswith("{"):
            logger.warning("LLM did not return valid JSON format.")
            return {"query": "", "description": "Invalid"}

        return json.loads(raw)
    except Exception as e:
        logger.warning(f"Failed to parse LLM query: {e}")
        return {"query": "", "description": "Invalid"}


def get_hosts_for_query(query, key):
    cache = load_query_cache()
    h = hash_query(query)
    if h in cache:
        logger.info("Using cached Shodan query")
        return cache[h]["ips"]
    r = requests.get(API_SEARCH, params={"key": key, "query": query})
    if r.status_code != 200:
        logger.warning(f"Query failed: {r.status_code}")
        return []
    matches = r.json().get("matches", [])
    ips = [m["ip_str"] for m in matches if "ip_str" in m]
    cache[h] = {"query": query, "ips": ips, "ts": datetime.now().isoformat()}
    save_query_cache(cache)
    return ips

def fetch_host(ip, key):
    try:
        r = requests.get(f"{API_HOST}{ip}?key={key}")
        if r.status_code == 200:
            return r.json()
        else:
            logger.warning(f"Host fetch failed for {ip}")
    except Exception as e:
        logger.warning(f"Exception getting host {ip}: {e}")
    return None

def chat_log_append(target, user_input, system_reply):
    log_file = Path("loot") / target / "chat_history.txt"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a") as f:
        f.write(f"\n[User] {user_input}\n[System] {system_reply}\n")

def recon_target(ip):
    os.environ["RECON_KI_TARGET"] = ip
    run_path = Path("loot") / ip / f"run{datetime.now().strftime('%Y%m%d%H%M%S')}"
    os.environ["RECON_KI_RUN_PATH"] = str(run_path)
    run_path.mkdir(parents=True, exist_ok=True)

    modules = [
        "modules/recon.py", "tools/shodan_enricher.py", "modules/scriptmind.py",
        "modules/cve.py", "tools/cve2exploit_map.py", "modules/exploit.py",
        "modules/post.py", "modules/render.py"
    ]
    for mod in modules:
        try:
            logger.info(f"[📦] Running {mod}")
            os.system(f"python3 {mod}")
        except:
            logger.warning(f"Module failed: {mod}")

def generate_response(user_input, lang, host_count, desc):
    prompt = f"""You are a multilingual recon assistant.
Reply in {lang}. User said: \"{user_input}\".
You generated the following description: {desc}.
You found {host_count} hosts. Respond conversationally but briefly in {lang}."""
    try:
        return use_llm("chat_react", prompt).strip()
    except:
        return f"[{lang}] Found {host_count} hosts. Proceeding."

def main():
    print("🧠 Where shall I reconAIssance? :", end=" ")
    user_input = input().strip()
    lang = detect_language(user_input)
    logger.info(f"Detected language: {lang}")

    parsed = query_shodan(user_input)
    query = parsed.get("query", "")
    desc = parsed.get("description", "")
    if not query:
        print("❌ Could not generate a valid Shodan query.")
        return

    print(f"🔍 {desc}")
    key = load_keys().get("shodan")
    if not key:
        print("❌ Missing Shodan API key.")
        return

    ips = get_hosts_for_query(query, key)
    for ip in ips:
        if not already_in_db(ip):
            data = fetch_host(ip, key)
            if data:
                append_to_db(data)
                logger.info(f"Stored host {ip} in DB")

    reply = generate_response(user_input, lang, len(ips), desc)
    print(f"🤖 {reply}")

    # Nur „critical“ Hosts exploiten
    critical_hosts = []
    risk_file = Path("loot/shodan_ai_risk.json")
    if risk_file.exists():
        try:
            risk_data = json.load(open(risk_file))
            critical_hosts = [r["ip"] for r in risk_data if r.get("risk") == "critical"]
            logger.info(f"Selected {len(critical_hosts)} critical host(s) for auto-recon.")
        except Exception as e:
            logger.warning(f"Risk parsing failed: {e}")
    else:
        logger.warning("shodan_ai_risk.json not found. No auto-exploit possible.")

    if critical_hosts:
        for ip in critical_hosts:
            recon_target(ip)
    else:
        print("⚠️ No critical targets selected for recon.")

    chat_log_append(query.replace(" ", "_")[:30], user_input, reply)

if __name__ == "__main__":
    main()
