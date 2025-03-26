import json
import logging
import time
from pathlib import Path
from shodan_lookup_db import shodan_search, enrich_host, store_in_db, already_in_db
from load_api_keys import load_keys

logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    fh = logging.FileHandler("recon_log.txt", mode="a")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)


def run_batch_lookup(queries):
    key = load_keys().get("shodan")
    if not key:
        logger.error("Shodan API key missing.")
        return

    for query in queries:
        print(f"🔍 {query}")
        ips = shodan_search(query, key)
        logger.info(f"Query '{query}' → {len(ips)} IPs")

        for ip in ips:
            if already_in_db(ip):
                logger.debug(f"[Skip] {ip} already in DB")
                continue
            host_data = enrich_host(ip, key)
            if host_data:
                store_in_db(host_data)
                logger.info(f"Stored {ip}")
                time.sleep(1.5)  # gentle delay for API


def interactive():
    file_path = input("Path to .json file with Shodan queries (list of strings): ").strip()
    path = Path(file_path)
    if not path.exists():
        print("❌ File not found.")
        return

    try:
        queries = json.load(open(path))
        if not isinstance(queries, list):
            print("❌ File must contain a list of queries.")
            return
        run_batch_lookup(queries)
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    interactive()
