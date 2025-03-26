import os
import sys
import json
import subprocess
import logging
from pathlib import Path
from datetime import datetime

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
from hash import find_sources, extract, guess_mode

def load_usernames(run_path):
    brute_file = os.path.join(run_path, "ssh_brute_result.json")
    if os.path.exists(brute_file):
        try:
            results = json.load(open(brute_file))
            users = list(set(r['user'] for r in results if 'user' in r))
            logger.info(f"Loaded {len(users)} usernames from brute result")
            return users
        except Exception as e:
            logger.warning(f"Failed to load usernames from brute file: {e}")
    logger.info("Fallback to default username: root")
    return ["root"]

def infer_crunch_args(target, usernames, hash_sample):
    logger.debug("Requesting crunch args via LLM...")
    prompt = f"""You are a password cracking strategist.
Given the following:
- Target: {target}
- Usernames: {', '.join(usernames)}
- Hash sample: {hash_sample}

Suggest optimized crunch arguments.

ONLY RETURN VALID JSON. Example:
{{"min_length":8,"max_length":12,"charset":"abcdefghijklmnopqrstuvwxyz0123456789","notes":"Optimized for typical web-apps"}}
"""
    try:
        result = use_llm("crunch_args", prompt)
        parsed = json.loads(result.strip().split("\n")[-1])
        logger.info(f"LLM crunch args: {parsed}")
        return parsed
    except json.JSONDecodeError as e:
        logger.warning("LLM crunch parsing failed – using fallback values")
        return {
            "min_length": 8,
            "max_length": 12,
            "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
            "notes": "LLM parse error: fallback to default"
        }

def build_crunch_pipe(run_path, args, mode):
    logger.info("Starting crunch + hashcat pipeline...")
    fifo = os.path.join(run_path, "crunchpipe")
    try:
        os.mkfifo(fifo)
    except FileExistsError:
        logger.debug("FIFO already exists – continuing")

    log = os.path.join(run_path, "hashcat_crack.log")
    hashes = os.path.join(run_path, "hashes.txt")

    crunch_cmd = ["crunch", str(args["min_length"]), str(args["max_length"]), args["charset"]]
    hashcat_cmd = ["hashcat", "-a", "0", "-m", mode, hashes, fifo, "--force", "--status"]

    with open(os.path.join(run_path, "crunch_args.json"), "w") as f:
        json.dump(args, f, indent=2)
        logger.info(f"Saved crunch args to crunch_args.json")

    try:
        with open(log, "w") as logfile:
            subprocess.Popen(crunch_cmd, stdout=open(fifo, "w"), stderr=logfile)
            subprocess.run(hashcat_cmd, stdout=logfile, stderr=subprocess.STDOUT)
        logger.info(f"Crunch pipeline finished. Log: {log}")
    except Exception as e:
        logger.exception("Error during crunch pipeline execution")

def fallback_pw_list(run_path, mode):
    logger.info("Running fallback dictionary attack...")
    pw_dir = Path("PW")
    if not pw_dir.exists():
        logger.warning("PW/ directory not found – skipping fallback wordlists")
        return
    hashes = os.path.join(run_path, "hashes.txt")
    log = os.path.join(run_path, "hashcat_fallback.log")
    for pwfile in pw_dir.glob("*.txt"):
        logger.info(f"[*] Fallback using: {pwfile.name}")
        subprocess.run([
            "hashcat", "-a", "0", "-m", mode, hashes, str(pwfile), "--force", "--status"
        ], stdout=open(log, "a"), stderr=subprocess.STDOUT)

def run(target, run_path):
    logger.info(f"Starting hash_crunch for {target}")
    files = find_sources(run_path)
    if not files:
        logger.warning("No hash source files found.")
        return

    hashes = []
    for f in files:
        try:
            with open(f, "r", errors="ignore") as fx:
                hashes += extract(fx.readlines())
        except Exception as e:
            logger.warning(f"Could not read {f}: {e}")
    if not hashes:
        logger.warning("No hashes extracted.")
        return

    out = os.path.join(run_path, "hashes.txt")
    with open(out, "w") as f:
        for h in hashes:
            f.write(h + "\n")
    logger.info(f"Saved {len(hashes)} hashes to {out}")

    mode, label = guess_mode(hashes[0])
    logger.info(f"Guessed hash mode: {label} ({mode})")
    usernames = load_usernames(run_path)
    args = infer_crunch_args(target, usernames, hashes[0])
    build_crunch_pipe(run_path, args, mode)
    fallback_pw_list(run_path, mode)
    logger.info("hash_crunch run complete.")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)
    run(t, p)
