import os
import sys
import json
import requests
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
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
    except Exception as e:
        print(f"[!] Error fetching Shodan data: {e}")
    return None

def extract_ip_from_recon(path):
    recon_file = os.path.join(path, "recon.txt")
    if not os.path.exists(recon_file):
        print("[!] recon.txt not found.")
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
        return {"summary": "No Shodan data available."}

    prompt = f"""Analyze the following Shodan data for IP {ip} for potential attack vectors:

Data: {json.dumps(shodan_data, indent=2)[:4000]}

ONLY RETURN VALID JSON. Example:
{{"summary": "Potential issues include outdated services, open ports, etc."}}
"""

    result = use_llm("shodan_analysis", prompt)
    try:
        summary_json = json.loads(result.strip().split("\n")[-1])
        return summary_json
    except json.JSONDecodeError:
        print(f"[!] LLM parse error: {result[:200]}")
        return {"summary": "LLM parse error"}

def run(target, run_path):
    output_file = os.path.join(run_path, "shodan_summary.json")
    results = {}
    ips = extract_ip_from_recon(run_path)
    if not ips:
        print("[!] No IP addresses extracted from recon.")
        return

    for ip in ips:
        print(f"[🌐] Querying Shodan for IP: {ip}")
        data = get_shodan_data(ip)
        analysis = analyze_with_llm(ip, data)
        results[ip] = {
            "shodan_raw": data,
            "llm_analysis": analysis.get("summary", "No analysis provided.")
        }

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[✓] Shodan analysis saved to {output_file}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        print("[!] Missing environment variables.")
        exit(1)
    run(t, p)
