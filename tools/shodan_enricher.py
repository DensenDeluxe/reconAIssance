import os
import json
import logging
from pathlib import Path

# Logging Setup
logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler("recon_log.txt", mode="a")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# Stichworterkennung
PORT_FLAGS = {
    22: "SSH open",
    23: "Telnet open",
    80: "HTTP open",
    443: "HTTPS open",
    3306: "MySQL open",
    3389: "RDP open"
}

CPE_KEYWORDS = {
    "nginx": "Possible outdated web server",
    "apache": "Apache detected",
    "openssh": "OpenSSH identified",
    "mysql": "MySQL exposed"
}

def enrich_shodan(run_path):
    logger.info("Running Shodan tag enrichment...")
    flat_path = Path(run_path) / "shodan_flat.json"
    out_path = Path(run_path) / "shodan_tags.json"

    if not flat_path.exists():
        logger.warning("No shodan_flat.json found. Skipping enrichment.")
        return

    try:
        flat_data = json.loads(flat_path.read_text())
    except Exception as e:
        logger.exception("Failed to load shodan_flat.json")
        return

    tagged = []
    for entry in flat_data:
        flags = []
        for port in entry.get("ports", []):
            if port in PORT_FLAGS:
                flags.append(PORT_FLAGS[port])

        for service in entry.get("services", []):
            for cpe in service.get("cpe", []):
                for keyword in CPE_KEYWORDS:
                    if keyword in cpe:
                        flags.append(CPE_KEYWORDS[keyword])
            banner = service.get("banner", "").lower()
            for keyword in CPE_KEYWORDS:
                if keyword in banner:
                    flags.append(f"{keyword} banner match")

        tagged.append({
            "ip": entry.get("ip"),
            "org": entry.get("org"),
            "location": entry.get("location"),
            "flags": sorted(set(flags))
        })

    try:
        with open(out_path, "w") as f:
            json.dump(tagged, f, indent=2)
        logger.info(f"Shodan tags saved to {out_path}")
    except Exception as e:
        logger.exception("Failed to write shodan_tags.json")

if __name__ == "__main__":
    path = os.getenv("RECON_KI_RUN_PATH")
    if not path:
        logger.error("Missing RECON_KI_RUN_PATH")
        exit(1)
    enrich_shodan(path)
