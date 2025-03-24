import os
import json
import re
from llm_wrapper import use_llm

MODULE_INDEX = "tools/msf_modules.json"

def load_inventory():
    if not os.path.exists(MODULE_INDEX):
        return []
    return json.load(open(MODULE_INDEX))

def llm_module_match(cve_id, context=""):
    prompt = f"""You are an expert in Metasploit.

Given the CVE and the target context, suggest the best Metasploit module.
Only suggest real module names, no guesses.

CVE: {cve_id}
Context: {context}

Return JSON:
{{ "module": "exploit/...", "reason": "..." }}"""

    result = use_llm("module_match", prompt, context)
    try:
        return json.loads(result.split("\n")[-1])
    except:
        return {"module": "", "reason": "LLM parse error"}

def validate_match(module_name, inventory):
    return any(m["name"] == module_name for m in inventory)

def suggest_module(cve_id, context=""):
    inventory = load_inventory()
    match = llm_module_match(cve_id, context)
    name = match.get("module", "")
    if not name:
        return {"valid": False, "module": None, "reason": match.get("reason", "no module")}
    valid = validate_match(name, inventory)
    return {
        "valid": valid,
        "module": name if valid else None,
        "reason": match.get("reason", "no reason"),
    }

if __name__ == "__main__":
    cve = input("CVE-ID: ").strip()
    ctx = input("Context (e.g. nginx): ").strip()
    result = suggest_module(cve, ctx)
    print(json.dumps(result, indent=2))
