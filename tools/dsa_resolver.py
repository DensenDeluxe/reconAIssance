import os
import sys
import json
from llm_wrapper import use_llm
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))

def resolve_dsa(dsa_id):
    prompt = f"""You are a CVE and Exploit Analyst.
Given this Debian Security Advisory (DSA) ID: {dsa_id}, provide:

- Short vulnerability summary
- Related CVEs
- Likely Metasploit module (if available)
- Suggested payload type
- Severity (low, medium, high, critical)

ONLY RETURN VALID JSON. Example:
{{
  "summary": "Short summary...",
  "related_cves": ["CVE-xxxx-xxxx"],
  "module_hint": "exploit/...",
  "suggested_payload": "linux/x86/meterpreter_reverse_tcp",
  "severity": "high"
}}
"""
    result = use_llm("dsa_resolver", prompt)
    try:
        data = json.loads(result.strip().split("\n")[-1])
    except json.JSONDecodeError:
        data = {
            "summary": "LLM parse error",
            "related_cves": [],
            "module_hint": "",
            "suggested_payload": "",
            "severity": "unknown"
        }
    return data

def run(target, run_path):
    dsa_file = os.path.join(run_path, "cve_summary.json")
    if not os.path.exists(dsa_file):
        print("[!] No cve_summary.json file found.")
        return

    raw = json.load(open(dsa_file))
    dsa_ids = [c for c in raw if c.startswith("DSA-")]
    if not dsa_ids:
        print("[!] No DSA identifiers found in cve_summary.json.")
        return

    results = {}
    for dsa in dsa_ids:
        print(f"[🧠] Resolving DSA: {dsa}")
        results[dsa] = resolve_dsa(dsa)

    out = os.path.join(run_path, "dsa_analysis.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[✓] DSA analysis saved to {out}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        print("[!] Missing environment variables.")
        exit(1)
    run(t, p)
