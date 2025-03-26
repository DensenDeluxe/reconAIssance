import os
import sys
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

def find_sources(path):
    logger.debug(f"Scanning for hash sources in: {path}")
    files = []
    for root, _, fs in os.walk(path):
        for f in fs:
            if f.lower() in ["shadow", ".htpasswd", "passwd", "sam"]:
                full_path = os.path.join(root, f)
                files.append(full_path)
                logger.info(f"Found hash source: {full_path}")
    return files

def extract(lines):
    h = []
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) > 1 and parts[1].startswith("$"):
            h.append(parts[1])
    logger.debug(f"Extracted {len(h)} hashes from file")
    return h

def guess_mode(sample):
    if sample.startswith("$6$"):
        return "1800", "SHA512crypt"
    if sample.startswith("$1$"):
        return "500", "MD5crypt"
    if sample.startswith("$2y$") or sample.startswith("$2a$"):
        return "3200", "bcrypt"
    return "0", "unknown"

def run(target, path):
    logger.info(f"Starting hash extraction for target: {target}")
    files = find_sources(path)
    hashes = []
    for f in files:
        try:
            with open(f, "r", errors="ignore") as fx:
                lines = fx.readlines()
                hashes += extract(lines)
        except Exception as e:
            logger.warning(f"Failed to read {f}: {e}")

    if not hashes:
        logger.info("No hashes found.")
        return

    out = os.path.join(path, "hashes.txt")
    with open(out, "w") as f:
        for h in hashes:
            f.write(h + "\n")
    logger.info(f"Saved {len(hashes)} hashes to {out}")

    mode, label = guess_mode(hashes[0])
    logger.info(f"Guessed hash mode: {label} (mode {mode})")
    cmd = f"hashcat -a 0 -m {mode} {out} rockyou.txt --force"
    command_file = os.path.join(path, "hashcat_command.txt")
    with open(command_file, "w") as f:
        f.write(cmd + "\n")
    logger.info(f"Wrote hashcat command to {command_file}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)
    run(t, p)
