import os
import sys
import json
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_logger import PromptLogger
from llm_wrapper import use_llm

def extract_services(text):
    services = []
    if "OpenSSH_" in text:
        services.append("openssh")
    if "nginx" in text.lower():
        services.append("nginx")
    return list(set(services))

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

def analyze_with_llm(cves):
    results = {}
    for cve in cves[:10]:
        prompt = f"What is the purpose and risk of CVE {cve['id']}?\n\nSummary: {cve.get('summary', '')}"
        response = use_llm("cve_analysis", prompt)
        results[cve["id"]] = {
            "summary": cve.get("summary", ""),
            "severity": cve.get("cvss", {}).get("severity", "unknown"),
            "score": cve.get("cvss", {}).get("score", "n/a"),
            "llm_analysis": response
        }
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
