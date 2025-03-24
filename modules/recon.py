import os
import sys
import subprocess
import requests
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_wrapper import use_llm

def tool_available(name):
    return subprocess.call(["which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def run(target, run_path):
    rc = os.path.join(run_path, "recon.rc")
    with open(rc, "w") as f:
        f.write(f"""use auxiliary/scanner/ssh/ssh_version
set RHOSTS {target}
run
use auxiliary/scanner/http/http_version
set RHOSTS {target}
run
use auxiliary/scanner/ssl/ssl_version
set RHOSTS {target}
run
exit""")
    subprocess.run(["msfconsole", "-q", "-r", rc],
                   stdout=open(os.path.join(run_path, "recon.txt"), "w"),
                   stderr=subprocess.DEVNULL,
                   text=True,
                   timeout=180)

    sub_path = os.path.join(run_path, "subdomains.txt")
    with open(sub_path, "w") as f:
        if tool_available("subfinder"):
            subprocess.run(["subfinder", "-d", target], stdout=f)
        if tool_available("amass"):
            subprocess.run(["amass", "enum", "-passive", "-d", target], stdout=f)

    takeover = []
    for line in open(sub_path):
        sub = line.strip()
        try:
            result = subprocess.run(["host", sub], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if "NXDOMAIN" in result.stdout or "not found" in result.stdout:
                takeover.append(sub)
        except:
            continue
    with open(os.path.join(run_path, "takeover_candidates.txt"), "w") as f:
        for s in takeover:
            f.write(s + "\n")

    gh_query = f"{target} password OR secret OR key OR token"
    headers = {'Accept': 'application/vnd.github.v3+json'}
    token_file = "tools/github_token.txt"
    if os.path.exists(token_file):
        headers["Authorization"] = f"token {open(token_file).read().strip()}"
    try:
        r = requests.get(f"https://api.github.com/search/code?q={gh_query}&per_page=10", headers=headers)
        leaks = r.json().get("items", [])
    except:
        leaks = []
    with open(os.path.join(run_path, "leaks_github.json"), "w") as f:
        json.dump(leaks, f, indent=2)

    prompt = f"List 5 likely people or roles that might currently work for or administer {target}."
    response = use_llm("staff_discovery", prompt)
    with open(os.path.join(run_path, "staff.txt"), "w") as f:
        f.write(response)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
