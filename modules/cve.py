import os
import sys
import json
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_logger import PromptLogger
from llm_wrapper import use_llm

CACHE_FILE = "tools/cve_analysis_cache.json"

def extract_services(text):
    services = set()
    if "OpenSSH_" in text:
        services.add("openssh")
    if "nginx" in text.lower():
        services.add("nginx")
    if "apache" in text.lower():
        services.add("apache")
    if "httpd" in text.lower():
        services.add("httpd")
    if "ssl" in text.lower():
        services.add("openssl")
    return list(services)

def query_osv(package_name):
    try:
        r = requests.post("https://api.osv.dev/v1/query", json={
            "package": {"name": package_name, "ecosystem": "Debian"}
        })
        if r.status_code == 200:
            return r.json().get("vulns", [])
    except:
        pass
    return []

def load_cache():
    if os.path.exists(CACHE_FILE):
        return json.load(open(CACHE_FILE))
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def analyze_with_llm(cves):
    results = {}
    cache = load_cache()

    for cve in cves[:10]:
        cve_id = cve['id']
        if cve_id in cache:
            results[cve_id] = cache[cve_id]
            continue

        prompt = f"""What is the purpose and risk of CVE {cve_id}?

Summary: {cve.get('summary', '')}

ONLY RETURN VALID JSON. Do NOT add explanations or notes outside JSON.
Example:
{{"summary": "...", "severity": "...", "score": "...", "llm_analysis": "..."}}
"""

        result = use_llm("cve_analysis", prompt)

        try:
            parsed_result = json.loads(result.split("\n")[-1])
        except json.JSONDecodeError:
            parsed_result = {
                "summary": cve.get('summary', ''),
                "severity": cve.get('cvss', {}).get('severity', 'unknown'),
                "score": cve.get('cvss', {}).get('score', 'n/a'),
                "llm_analysis": f"LLM parse error: {result[:200]}"
            }

        results[cve_id] = parsed_result
        cache[cve_id] = parsed_result

    save_cache(cache)
    return results

def run(target, run_path):
    recon_file = os.path.join(run_path, "recon.txt")
    if not os.path.exists(recon_file):
        return
    services = extract_services(open(recon_file).read())
    all_cves = []
    for s in services:
        all_cves += query_osv(s)
    results = analyze_with_llm(all_cves)
    with open(os.path.join(run_path, "cve_summary.json"), "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
