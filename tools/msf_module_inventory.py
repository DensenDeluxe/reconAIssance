import os
import json
import re

BASE_DIRS = [
    "/opt/metasploit-framework/embedded/framework/modules",
    os.path.expanduser("~/.msf4/modules")
]

OUTFILE = "tools/msf_modules.json"

def parse_module(file_path):
    try:
        text = open(file_path, "r", errors="ignore").read()
        rel_path = os.path.relpath(file_path, start="/opt/metasploit-framework/")
        cves = re.findall(r"(CVE-\d{4}-\d{4,7})", text)
        platforms = re.findall(r'Platform(?:s)?:\s*(\w+)', text)
        targets = re.findall(r'Target(?:s)?:\s*(.+)', text)
        payloads = re.findall(r'Set PAYLOAD ([\w/]+)', text)
        name_match = re.search(r'module\s+([:\w\/]+)', text)
        name = name_match.group(1) if name_match else rel_path.replace(".rb", "")
        return {
            "name": name,
            "path": file_path,
            "rel_path": rel_path,
            "cves": list(set(cves)),
            "platforms": list(set(platforms)),
            "targets": list(set(targets)),
            "payloads": list(set(payloads))
        }
    except Exception as e:
        return None

def collect_modules():
    modules = []
    for base in BASE_DIRS:
        if not os.path.exists(base):
            continue
        for root, _, files in os.walk(base):
            for file in files:
                if file.endswith(".rb"):
                    full_path = os.path.join(root, file)
                    data = parse_module(full_path)
                    if data:
                        modules.append(data)

    os.makedirs("tools", exist_ok=True)
    with open(OUTFILE, "w") as f:
        json.dump(modules, f, indent=2)
    print(f"[✓] Saved {len(modules)} modules to {OUTFILE}")

if __name__ == "__main__":
    collect_modules()
