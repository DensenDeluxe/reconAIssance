import os
import subprocess
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

def build_rc(sub, rc):
    logger.debug(f"Building RC script for subdomain: {sub}")
    lines = [
        f"use auxiliary/scanner/ssh/ssh_version",
        f"set RHOSTS {sub}",
        "run",
        "use auxiliary/scanner/http/http_version",
        f"set RHOSTS {sub}",
        "run",
        "use auxiliary/scanner/ssl/ssl_version",
        f"set RHOSTS {sub}",
        "run",
        "exit"
    ]
    with open(rc, "w") as f:
        f.write("\n".join(lines))
    logger.info(f"RC script created at: {rc}")

def scan(sub, path):
    tag = sub.replace(".", "_")
    rc = os.path.join(path, f"recon_sub_{tag}.rc")
    out = os.path.join(path, f"recon_sub_{tag}.txt")
    build_rc(sub, rc)
    try:
        logger.info(f"Scanning subdomain with Metasploit: {sub}")
        subprocess.run(["msfconsole", "-q", "-r", rc],
                       stdout=open(out, "w"),
                       stderr=subprocess.DEVNULL,
                       text=True,
                       timeout=180)
        logger.info(f"Scan complete: {out}")
    except Exception as e:
        logger.exception(f"Scan failed for {sub}")

def run(target, path):
    logger.info(f"Running subdomain recon for target: {target}")
    subfile = os.path.join(path, "subdomains.txt")
    if not os.path.exists(subfile):
        logger.warning("No subdomains.txt found – skipping subdomain scanning.")
        return

    with open(subfile, "r") as f:
        subs = [l.strip() for l in f if l.strip()]
    logger.info(f"Loaded {len(subs)} subdomains for scanning.")
    
    for sub in subs:
        scan(sub, path)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)
    run(t, p)
