import os
import json
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_wrapper import use_llm

def run(target, run_path):
    cls_file = os.path.join(run_path, "superscript_class.json")
    if not os.path.exists(cls_file):
        print("[!] No superscript_class.json found.")
        return

    data = json.load(open(cls_file))
    effect = data.get("effect", "unknown")
    category = data.get("class", "none")
    note = data.get("note", "")

    prompt = f"""You are a CVE analyst. Given the following attack classification from a userscript executed on https://{target}, infer likely CVEs.

Classification: {category}
Effect level: {effect}
Notes: {note}

ONLY RETURN VALID JSON. Example:
{{"cves": ["CVE-2023-1234", "CVE-2022-5678"]}}
"""

    result = use_llm("scriptmind_cve_infer", prompt)
    try:
        matches_json = json.loads(result.strip().split("\n")[-1])
        matches = matches_json.get("cves", [])
    except json.JSONDecodeError:
        matches = []
        print(f"[!] LLM parse error: {result[:200]}")

    with open(os.path.join(run_path, "superscript_cve_infer.json"), "w") as f:
        json.dump({"inferred_cves": matches}, f, indent=2)

    print(f"[✓] CVEs inferred and saved: {matches}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        print("[!] Missing environment variables.")
        exit(1)
    run(t, p)
