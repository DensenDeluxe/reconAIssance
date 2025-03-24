import os
import sys
import json
import requests
from datetime import datetime
from llm_wrapper import use_llm

API_KEY_FILE = "tools/shodan_token.txt"
API_URL = "https://api.shodan.io/shodan/host/"

def get_shodan_data(ip):
    if not os.path.exists(API_KEY_FILE):
        print("[!] No Shodan token found. Skipping.")
        return None
    key = open(API_KEY_FILE).read().strip()
    try:
        r = requests.get(f"{API_URL}{ip}?key={key}")
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def extract_ip_from_recon(path):
    recon_file = os.path.join(path, "recon.txt")
    if not os.path.exists(recon_file):
        return []
    with open(recon_file) as f:
        lines = f.read()
    ips = set()
    for line in lines.split("\n"):
        parts = line.strip().split()
        for p in parts:
            if p.count(".") == 3:
                ips.add(p)
    return list(ips)

def analyze_with_llm(ip, shodan_data):
    if not shodan_data:
        return "No Shodan data available."
    prompt = f"""Analyze the following Shodan data for potential attack vectors:

IP: {ip}

Data:
{json.dumps(shodan_data, indent=2)[:4000]}

Return a brief summary of risks and services."""
    result = use_llm("shodan_analysis", prompt)
    return result.strip()

def run(target, run_path):
    output_file = os.path.join(run_path, "shodan_summary.json")
    results = {}
    for ip in extract_ip_from_recon(run_path):
        print(f"[🌐] Querying Shodan for: {ip}")
        data = get_shodan_data(ip)
        analysis = analyze_with_llm(ip, data)
        results[ip] = {
            "shodan_raw": data,
            "llm_analysis": analysis
        }
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[✓] Shodan results saved to: {output_file}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
