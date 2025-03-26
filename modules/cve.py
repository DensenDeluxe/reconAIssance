import os
import sys
import json
import requests
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
from llm_logger import PromptLogger
from llm_wrapper import use_llm

CACHE_FILE = "tools/cve_analysis_cache.json"

def extract_services(text):
    logger.debug("Extracting services from recon output...")
    services = set()
    if "OpenSSH_" in text:
        services.add("openssh")
    if "nginx" in text.lower():
        services.add("nginx")
    if "apache" in text.lower():
        services.add("apache")
    if "httpd" in text.lower():
        services.add("httpd")
    if "ssl" in text.lower():
        services.add("openssl")
    logger.info(f"Identified services: {list(services)}")
    return list(services)

def query_osv(package_name):
    logger.debug(f"Querying OSV for: {package_name}")
    try:
        r = requests.post("https://api.osv.dev/v1/query", json={
            "package": {"name": package_name, "ecosystem": "Debian"}
        })
        if r.status_code == 200:
            vulns = r.json().get("vulns", [])
            logger.info(f"Found {len(vulns)} CVEs for {package_name}")
            return vulns
        else:
            logger.warning(f"OSV query failed for {package_name} with status {r.status_code}")
    except Exception as e:
        logger.exception(f"Error querying OSV for {package_name}")
    return []

def load_cache():
    if os.path.exists(CACHE_FILE):
        logger.debug("Loading CVE analysis cache...")
        try:
            return json.load(open(CACHE_FILE))
        except Exception as e:
            logger.warning("Failed to load CVE cache.")
    return {}

def save_cache(cache):
    logger.debug("Saving updated CVE cache.")
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        logger.warning("Failed to save CVE cache.")

def analyze_with_llm(cves):
    logger.debug("Starting LLM analysis of CVEs...")
    results = {}
    cache = load_cache()

    for cve in cves[:10]:
        cve_id = cve.get('id', 'unknown')
        if cve_id in cache:
            logger.info(f"Using cached analysis for {cve_id}")
            results[cve_id] = cache[cve_id]
            continue

        prompt = f"""What is the purpose and risk of CVE {cve_id}?

Summary: {cve.get('summary', '')}

ONLY RETURN VALID JSON. Do NOT add explanations or notes outside JSON.
Example:
{{"summary": "...", "severity": "...", "score": "...", "llm_analysis": "..."}}
"""

        logger.debug(f"Sending CVE {cve_id} to LLM...")
        try:
            result = use_llm("cve_analysis", prompt)
        except Exception as e:
            logger.exception(f"LLM call failed for {cve_id}")
            result = "[!] LLM call failed"

        try:
            parsed_result = json.loads(result.split("\n")[-1])
        except Exception:
            logger.warning(f"Failed to parse LLM output for {cve_id}")
            parsed_result = {
                "summary": cve.get('summary', ''),
                "severity": cve.get('cvss', {}).get('severity', 'unknown'),
                "score": cve.get('cvss', {}).get('score', 'n/a'),
                "llm_analysis": f"LLM parse error or failed: {str(result)[:200]}"
            }

        results[cve_id] = parsed_result
        cache[cve_id] = parsed_result

    save_cache(cache)
    logger.info("LLM analysis complete.")
    return results

def run(target, run_path):
    logger.info(f"Running CVE module for target: {target}")
    recon_file = os.path.join(run_path, "recon.txt")
    if not os.path.exists(recon_file):
        logger.error(f"Missing recon.txt at {recon_file}")
        return

    try:
        with open(recon_file) as f:
            recon_data = f.read()
        services = extract_services(recon_data)
        if not services:
            logger.warning("No services extracted – skipping CVE queries.")
            return
        all_cves = []
        for s in services:
            all_cves += query_osv(s)
        if not all_cves:
            logger.warning("No CVEs returned from OSV queries.")
            return
        results = analyze_with_llm(all_cves)
        output_path = os.path.join(run_path, "cve_summary.json")
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"CVE summary saved to {output_path}")
    except Exception as e:
        logger.exception("CVE module failed unexpectedly.")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("RECON_KI_TARGET or RECON_KI_RUN_PATH is not set.")
        exit(1)
    run(t, p)
