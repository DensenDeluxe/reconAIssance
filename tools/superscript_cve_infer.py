import os
import json
from llm_wrapper import use_llm

def run(target, run_path):
    cls_file = os.path.join(run_path, "superscript_class.json")
    if not os.path.exists(cls_file):
        print("[!] No classification data found.")
        return

    data = json.load(open(cls_file))
    effect = data.get("effect", "unknown")
    category = data.get("class", "none")
    note = data.get("note", "")

    prompt = f"""You are a CVE analyst.

Given this attack classification from a user script executed on https://{target}, infer likely CVEs.

Classification: {category}
Effect level: {effect}
Notes: {note}

Return a JSON list of matching CVE IDs (max 10)."""

    result = use_llm("scriptmind_cve_infer", prompt)
    try:
        matches = json.loads(result.split("\n")[-1])
    except:
        matches = []

    with open(os.path.join(run_path, "superscript_cve_infer.json"), "w") as f:
        json.dump(matches, f, indent=2)

    print(f"[✓] Inferred CVEs from classification: {matches}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
