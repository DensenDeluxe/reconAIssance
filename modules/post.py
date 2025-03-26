import os
import sys
import subprocess
import requests
import json
import logging

# Logging Setup
logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    file_handler = logging.FileHandler("recon_log.txt", mode='a')
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_wrapper import use_llm

def tool_available(name):
    available = subprocess.call(["which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    logger.debug(f"Tool check: {name} → {'found' if available else 'not found'}")
    return available

def run(target, run_path):
    logger.info(f"Starting recon module for: {target}")
    
    # Metasploit RC
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
    try:
        subprocess.run(["msfconsole", "-q", "-r", rc],
                       stdout=open(os.path.join(run_path, "recon.txt"), "w"),
                       stderr=subprocess.DEVNULL,
                       text=True,
                       timeout=180)
        logger.info("Metasploit scan complete.")
    except Exception as e:
        logger.exception("Metasploit scan failed")

    # Subdomain enumeration
    sub_path = os.path.join(run_path, "subdomains.txt")
    with open(sub_path, "w") as f:
        if tool_available("subfinder"):
            logger.info("Running subfinder...")
            subprocess.run(["subfinder", "-d", target], stdout=f)
        if tool_available("amass"):
            logger.info("Running amass...")
            subprocess.run(["amass", "enum", "-passive", "-d", target], stdout=f)

    # Takeover candidates
    takeover = []
    try:
        for line in open(sub_path):
            sub = line.strip()
            try:
                result = subprocess.run(["host", sub], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                if "NXDOMAIN" in result.stdout or "not found" in result.stdout:
                    takeover.append(sub)
            except Exception as e:
                logger.warning(f"DNS check failed for {sub}: {e}")
    except Exception as e:
        logger.warning("Failed to parse subdomain file.")

    takeover_path = os.path.join(run_path, "takeover_candidates.txt")
    with open(takeover_path, "w") as f:
        for s in takeover:
            f.write(s + "\n")
    logger.info(f"Saved {len(takeover)} takeover candidates.")

    # GitHub leak search
    gh_query = f"{target} password OR secret OR key OR token"
    headers = {'Accept': 'application/vnd.github.v3+json'}
    token_file = "tools/github_token.txt"
    if os.path.exists(token_file):
        headers["Authorization"] = f"token {open(token_file).read().strip()}"
        logger.debug("Using GitHub token for API access.")
    try:
        r = requests.get(f"https://api.github.com/search/code?q={gh_query}&per_page=10", headers=headers)
        leaks = r.json().get("items", [])
        logger.info(f"GitHub leak check returned {len(leaks)} results.")
    except Exception as e:
        logger.exception("GitHub leak search failed")
        leaks = []

    with open(os.path.join(run_path, "leaks_github.json"), "w") as f:
        json.dump(leaks, f, indent=2)

    # Staff guessing via LLM
    prompt = f"""List 5 likely roles or staff members at {target}.

ONLY RETURN VALID JSON. Example:
{{"staff":["Administrator","Developer","Security Analyst","Support","Manager"]}}
"""
    logger.debug("Requesting staff guess via LLM...")
    response = use_llm("staff_discovery", prompt)
    try:
        staff = json.loads(response.strip().split("\n")[-1])
        logger.info("LLM staff list parsed successfully.")
    except json.JSONDecodeError:
        logger.warning("Failed to parse LLM response – fallback used.")
        staff = {"staff": [], "error": f"LLM parse error: {response[:200]}"}

    staff_path = os.path.join(run_path, "staff.json")
    with open(staff_path, "w") as f:
        json.dump(staff, f, indent=2)

    logger.info(f"Staff analysis saved to {staff_path}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)
    run(t, p)
