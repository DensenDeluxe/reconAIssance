import os
import json
import re
from llm_wrapper import use_llm

MODULE_INDEX = "tools/msf_modules.json"
CACHE_FILE = "tools/llm_module_cache.json"

def load_inventory():
    if not os.path.exists(MODULE_INDEX):
        return []
    return json.load(open(MODULE_INDEX))

def load_cache():
    if os.path.exists(CACHE_FILE):
        return json.load(open(CACHE_FILE))
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def llm_module_match(cve_id, context=""):
    cache = load_cache()
    if cve_id in cache:
        return cache[cve_id]

    prompt = f"""You are an expert in Metasploit.
Given the CVE and the target context, suggest the best Metasploit module.
Only suggest real module names, no guesses.

CVE: {cve_id}
Context: {context}

ONLY RETURN VALID JSON. Do NOT add any explanations. Example:
{{ "module": "exploit/linux/http/apache_mod_ssl", "reason": "Exploits CVE-2002-1568 mod_ssl vulnerability." }}"""

    result = use_llm("module_match", prompt, context)

    try:
        json_result = json.loads(result.split("\n")[-1])
    except:
        json_result = {
            "module": "",
            "reason": f"LLM parse error: {result[:200]}"
        }

    cache[cve_id] = json_result
    save_cache(cache)
    return json_result

def validate_match(module_name, inventory):
    return any(m["name"] == module_name for m in inventory)

def suggest_module(cve_id, context=""):
    inventory = load_inventory()
    match = llm_module_match(cve_id, context)
    name = match.get("module", "")
    if not name:
        return {
            "valid": False,
            "module": None,
            "reason": match.get("reason", "No module returned from LLM")
        }
    valid = validate_match(name, inventory)
    return {
        "valid": valid,
        "module": name if valid else None,
        "reason": match.get("reason", "No reason given"),
    }

if __name__ == "__main__":
    cve = input("CVE-ID: ").strip()
    ctx = input("Context (e.g. nginx): ").strip()
    result = suggest_module(cve, ctx)
    print(json.dumps(result, indent=2))
