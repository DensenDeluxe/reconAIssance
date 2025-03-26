import os
import json
import sys
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_wrapper import use_llm

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

def run(target, run_path):
    logger.info(f"Running CVE inference for target: {target}")
    cls_file = os.path.join(run_path, "superscript_class.json")
    if not os.path.exists(cls_file):
        logger.warning("No superscript_class.json found. Skipping CVE inference.")
        return

    try:
        data = json.load(open(cls_file))
    except Exception as e:
        logger.exception("Failed to read superscript_class.json")
        return

    effect = data.get("effect", "unknown")
    category = data.get("class", "none")
    note = data.get("note", "")

    prompt = f"""You are a CVE analyst.
Given the following userscript analysis:

Classification: {category}
Effect level: {effect}
Notes: {note}

ONLY RETURN VALID JSON. No explanations or notes. Example:
{{"cves": ["CVE-2015-1632", "CVE-2023-12345"]}}
"""
    logger.debug("Sending CVE inference prompt to LLM")
    result = use_llm("scriptmind_cve_infer", prompt)

    try:
        matches_json = json.loads(result.strip().split("\n")[-1])
        matches = matches_json.get("cves", [])
        logger.info(f"Inferred CVEs: {matches}")
    except json.JSONDecodeError:
        logger.warning(f"LLM CVE parse error: {result[:200]}")
        matches = []

    out_file = os.path.join(run_path, "superscript_cve_infer.json")
    try:
        with open(out_file, "w") as f:
            json.dump({"inferred_cves": matches}, f, indent=2)
        logger.info(f"CVE inference saved to: {out_file}")
    except Exception as e:
        logger.exception("Failed to write superscript_cve_infer.json")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)
    run(t, p)
