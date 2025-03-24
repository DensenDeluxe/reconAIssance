import os
import sys
import json
from llm_wrapper import use_llm
from datetime import datetime

def resolve_dsa(dsa_id):
    prompt = f"""You are a CVE and Exploit Analyst.
Given this Debian Security Advisory ID, provide:
- A short vulnerability summary
- Possibly related CVEs
- A likely Metasploit module path (if any)
- A suggested payload type
- A severity level (low, medium, high, critical)

DSA ID: {dsa_id}

Return JSON:
{{
  "summary": "...",
  "related_cves": ["..."],
  "module_hint": "exploit/...",
  "suggested_payload": "...",
  "severity": "...",
  "reason": "..."
}}
"""
    result = use_llm("dsa_resolver", prompt)
    try:
        data = json.loads(result.split("\n")[-1])
    except:
        data = {
            "summary": "LLM parse error",
            "related_cves": [],
            "module_hint": "",
            "suggested_payload": "",
            "severity": "unknown",
            "reason": "No valid JSON returned"
        }
    return data

def run(target, run_path):
    dsa_file = os.path.join(run_path, "cve_summary.json")
    if not os.path.exists(dsa_file):
        return

    raw = json.load(open(dsa_file))
    dsa_ids = [c for c in raw if c.startswith("DSA-")]
    if not dsa_ids:
        return

    results = {}
    for dsa in dsa_ids:
        print(f"[🧠] Resolving DSA: {dsa} ...")
        results[dsa] = resolve_dsa(dsa)

    out = os.path.join(run_path, "dsa_analysis.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[✓] DSA resolution saved to: dsa_analysis.json")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
