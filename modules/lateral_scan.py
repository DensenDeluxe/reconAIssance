import os
import sys
import subprocess
import ipaddress
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

def extract_ip(log_path):
    logger.debug(f"Extracting IP from: {log_path}")
    try:
        with open(log_path, "r") as f:
            lines = f.readlines()
        for line in lines:
            if "inet " in line and "127." not in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[1].split("/")[0]
                    logger.info(f"Found IP for lateral scan: {ip}")
                    return ip
    except Exception as e:
        logger.warning(f"Failed to extract IP: {e}")
    logger.warning("No valid IP found.")
    return None

def run_lateral_scan(my_ip, run_path):
    logger.info(f"Starting lateral scan from {my_ip}")
    try:
        base = ipaddress.IPv4Interface(f"{my_ip}/24").network
        targets = [str(ip) for ip in base.hosts() if str(ip) != my_ip]
        logger.debug(f"Generated {len(targets)} IPs to scan in subnet")

        out_file = os.path.join(run_path, "lateral_scan.txt")
        with open(out_file, "w") as f:
            for ip in targets:
                try:
                    result = subprocess.run(
                        ["nc", "-zvw", "1", ip, "22", "80", "443"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=5
                    )
                    f.write(f"{ip}:\n{result.stdout}\n")
                    logger.debug(f"Scanned {ip}: success")
                except Exception as e:
                    error_msg = f"{ip}: error {e}"
                    f.write(error_msg + "\n")
                    logger.warning(error_msg)
        logger.info(f"Lateral scan results saved to: {out_file}")
    except Exception as e:
        logger.exception("Lateral scan failed.")

def run(target, run_path):
    logger.info(f"Running lateral scan module for target: {target}")
    log_file = os.path.join(run_path, "meterpreter.txt")
    if not os.path.exists(log_file):
        logger.error(f"Post-exploitation log not found: {log_file}")
        return

    ip = extract_ip(log_file)
    if not ip:
        logger.warning("No IP found in post-exploitation log.")
        return

    run_lateral_scan(ip, run_path)
    logger.info("Lateral scan complete.")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        logger.error("Missing RECON_KI_TARGET or RECON_KI_RUN_PATH")
        exit(1)
    run(t, p)
