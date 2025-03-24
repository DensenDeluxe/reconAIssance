import os
import sys
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from threading import Thread
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_wrapper import use_llm
from superscript_cve_infer import run as infer_cves_from_class

COUNT = int(os.getenv("RECON_SM_COUNT", "5"))
ITER = int(os.getenv("RECON_SM_ITER", "2"))
CACHE_FILE = "tools/scriptmind_cache.json"

def load_cache():
    if os.path.exists(CACHE_FILE):
        return json.load(open(CACHE_FILE))
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def start_superscript_server(run_path):
    os.chdir(run_path)
    Thread(target=lambda: os.system("python3 -m http.server 8080"), daemon=True).start()

def select_focus_mode(target, run_path):
    prompt = f"""Choose an attack focus for the website: https://{target}.

ONLY RETURN VALID JSON. Example:
{{"focus_mode": "xss", "reason": "Site likely vulnerable to XSS"}}
"""

    result = use_llm("focus_selection", prompt)
    try:
        return json.loads(result.strip().split("\n")[-1])
    except json.JSONDecodeError:
        return {"focus_mode": "full", "reason": "LLM parse error"}

def generate_script_batch(target, focus_mode, run_path, count):
    scripts = []
    for i in range(count):
        prompt = f"""Create a Violentmonkey-compatible userscript targeting https://{target} with attack focus '{focus_mode}'. 

ONLY RETURN THE USERSCRIPT CODE. No explanations."""
        content = use_llm("script_generation", prompt)
        name = f"gen_{i+1}_{datetime.now().strftime('%H%M%S')}.user.js"
        full_path = os.path.join(run_path, name)
        with open(full_path, "w") as f:
            f.write(content)
        scripts.append({"name": name, "path": full_path, "content": content})
    return scripts

def test_script_once(script_content, target):
    html, console = "", ""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.add_init_script(script_content)
            page.goto(f"https://{target}", timeout=20000)
            page.wait_for_timeout(5000)
            html = page.content()
            console = page.evaluate("() => console.log?.toString?.() || 'no log'")
            page.close()
            browser.close()
    except Exception as e:
        console = str(e)
    return html, console

def evaluate_superscript(script_path, target, run_path):
    script_content = Path(script_path).read_text()

    prompt = f"""Evaluate the effectiveness and potential vulnerabilities triggered by this userscript on https://{target}.

Script:
{script_content[:3000]}

ONLY RETURN VALID JSON. Example:
{{"effect": "high", "class": "xss", "module": ["exploit/..."], "note": "Cross-site scripting detected."}}
"""

    result = use_llm("script_evaluation", prompt)
    try:
        parsed = json.loads(result.strip().split("\n")[-1])
    except json.JSONDecodeError:
        parsed = {
            "effect": "unknown",
            "class": "unknown",
            "module": [],
            "note": f"LLM parse error: {result[:200]}"
        }

    class_file = os.path.join(run_path, "superscript_class.json")
    with open(class_file, "w") as f:
        json.dump(parsed, f, indent=2)

    if parsed['effect'] in ["high", "medium"]:
        infer_cves_from_class(target, run_path)

def run_scriptmind_loop(target, run_path):
    cache = load_cache()

    print(f"[→] ScriptMind running for {target}")
    focus_data = select_focus_mode(target, run_path)
    focus = focus_data.get("focus_mode", "full")

    cache_key = f"{target}_{focus}"
    if cache_key in cache:
        print("[⚡] Using cached superscript evaluation.")
        return

    all_scripts = []
    for i in range(ITER):
        batch = generate_script_batch(target, focus, run_path, COUNT)
        for script in batch:
            evaluate_superscript(script["path"], target, run_path)
            all_scripts.append(script["path"])

    cache[cache_key] = {"scripts_tested": all_scripts, "timestamp": str(datetime.now())}
    save_cache(cache)

    start_superscript_server(run_path)

    try:
        effect = json.load(open(os.path.join(run_path, "superscript_class.json"))).get("effect", "")
        if effect in ["low", "neutral", "unknown"]:
            print("[↻] Low effect detected, retrying with new focus...")
            run_scriptmind_loop(target, run_path)
    except Exception as e:
        print(f"[!] Error during recursive evaluation: {e}")

if __name__ == "__main__":
    target = os.getenv("RECON_KI_TARGET")
    run_path = os.getenv("RECON_KI_RUN_PATH")
    if not target or not run_path:
        print("[!] Missing environment variables.")
        exit(1)
    run_scriptmind_loop(target, run_path)

