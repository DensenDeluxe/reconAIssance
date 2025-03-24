import subprocess
import os
import json
import zipfile
import re
from datetime import datetime
from pathlib import Path

def get_desktop():
    try:
        d = os.popen("xdg-user-dir DESKTOP").read().strip()
        if os.path.isdir(d):
            return d
    except:
        pass
    return os.path.join(Path.home(), "Desktop")

def safe_name(name):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', name)

def run_module(module_path):
    print(f"[📦] Running: {module_path}")
    subprocess.run(["python3", module_path], check=True)

def session_exists(run_path):
    sid_file = os.path.join(run_path, "session_ids.txt")
    return os.path.exists(sid_file) and Path(sid_file).read_text().strip()

def ssh_success(run_path):
    path = os.path.join(run_path, "ssh_brute_result.json")
    if not os.path.exists(path):
        return False
    with open(path) as f:
        return any(r.get("success") for r in json.load(f))

def export_zip(target, run_path):
    try:
        safe_target = safe_name(target)
        name = f"ReconAIssance_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = os.path.join(get_desktop(), name)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(run_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, run_path)
                    zipf.write(full_path, arcname=rel_path)
        os.chmod(zip_path, 0o644)
        print(f"[✅] Exported to desktop: {zip_path}")
    except Exception as e:
        print(f"[❌] ZIP export failed: {e}")

def parse_targets(raw):
    parts = re.split(r"[,\s]+", raw.strip())
    return list(set([p for p in parts if p]))

def check_superscript_trigger(run_path):
    f = os.path.join(run_path, "superscript_class.json")
    if not os.path.exists(f): return
    try:
        data = json.load(open(f))
        if data.get("class") == "exploit" and data.get("effect") in ["high", "medium"]:
            print("[💣] Superscript classified as exploit → launching exploit.py")
            run_module("modules/exploit.py")
    except: pass

ascii_banner = r"""
  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$          
 /$$__  $$ /$$__  $$ /$$_____/ /$$__  $$| $$__  $$         
| $$  \__/| $$$$$$$$| $$      | $$  \ $$| $$  \ $$         
| $$      | $$_____/| $$      | $$  | $$| $$  | $$         
| $$      |  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$         
|__/       \_______/ \_______/ \______/ |__/  |__/         
                                                           
  /$$$$$$  /$$$$$$                                         
 /$$__  $$|_  $$_/                                         
| $$  \ $$  | $$                                            
| $$$$$$$$  | $$                                            
| $$__  $$  | $$                                            
| $$  | $$  | $$                                            
| $$  | $$ /$$$$$$                                         
|__/  |__/|______/                                         
                                                           
  /$$$$$$$ /$$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$ 
 /$$_____//$$_____/ |____  $$| $$__  $$ /$$_____/ /$$__  $$
|  $$$$$$|  $$$$$$   /$$$$$$$| $$  \ $$| $$      | $$$$$$$$
 \____  $$\____  $$ /$$__  $$| $$  | $$| $$      | $$_____/
 /$$$$$$$//$$$$$$$/|  $$$$$$$| $$  | $$|  $$$$$$$|  $$$$$$$
|_______/|_______/  \_______/|__/  |__/ \_______/ \_______/
"""

print(ascii_banner)
print("🔧 ReconAIssance – Multi-Target + Full-Auto Mode\n")

print("Choose input mode:")
print(" [1] Manual input")
print(" [2] From input.txt")
mode = input("Selection: ").strip()

if mode == "2" and os.path.exists("input.txt"):
    raw_input = Path("input.txt").read_text()
else:
    raw_input = input("Enter one or more targets: ")

targets = parse_targets(raw_input)
if not targets:
    print("❌ No valid targets.")
    exit(1)

modules = [
    "modules/recon.py",
    "modules/scriptmind.py",
    "tools/scriptmind_chart.py",
    "modules/recon_subdomains.py",
    "modules/cve.py",
    "tools/dsa_resolver.py",
    "tools/cve2exploit_map.py",
    "modules/exploit.py",
    "modules/sshchain.py",
    "modules/post.py",
    "modules/lateral_scan.py",
    "modules/hash.py",
    "modules/hash_crunch.py",
    "modules/render.py"
]

for target in targets:
    print(f"\n🚀 Starting ReconAIssance for: {target}")
    safe = safe_name(target)
    run_path = os.path.join("loot", safe, f"run{datetime.now().strftime('%Y%m%d%H%M%S')}")
    os.makedirs(run_path, exist_ok=True)
    os.environ["RECON_KI_TARGET"] = target
    os.environ["RECON_KI_RUN_PATH"] = run_path
    os.environ["RECON_SM_COUNT"] = "10"
    os.environ["RECON_SM_ITER"] = "3"

    for m in modules:
        try:
            run_module(m)
        except subprocess.CalledProcessError:
            print(f"[❌] Failed: {m}")
            break

    check_superscript_trigger(run_path)

    if not session_exists(run_path) and not ssh_success(run_path):
        print("[⚠️] No session found → launching fallback brute")
        try:
            run_module("modules/fallback_brute.py")
        except: pass

    export_zip(target, run_path)

    try:
        from tools.pdf_report import generate_pdf_report
        generate_pdf_report(target, run_path)
    except Exception as e:
        print(f"[❌] PDF generation failed: {e}")

print("\n✅ All targets processed.")