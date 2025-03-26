import json
from pathlib import Path
from llm_wrapper import use_llm
import logging

logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    fh = logging.FileHandler("recon_log.txt", mode="a")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)

DB_FILE = Path("loot/shodan_db.jsonl")
OUT_FILE = Path("loot/shodan_ai_risk.json")


def analyze_entry(entry):
    prompt = f"""You are a vulnerability analyst.
Given the following Shodan host data, evaluate the security risk.
Return a JSON object like:
{{"ip": "...", "risk": "low|medium|high|critical", "notes": "..."}}

Host:
{json.dumps(entry)[:3000]}

ONLY return JSON."""
    try:
        result = use_llm("shodan_db_ai", prompt)
        last = result.strip().split("\n")[-1]
        return json.loads(last)
    except Exception as e:
        logger.warning(f"Failed to analyze host {entry.get('ip_str')}: {e}")
        return None


def run():
    if not DB_FILE.exists():
        print("❌ No Shodan DB found.")
        return

    results = []
    seen_ips = set()

    with open(DB_FILE) as f:
        for line in f:
            try:
                entry = json.loads(line)
                ip = entry.get("ip_str")
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                analysis = analyze_entry(entry)
                if analysis:
                    results.append(analysis)
            except:
                continue

    with open(OUT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"✅ Risk analysis written to: {OUT_FILE}")
    logger.info(f"Wrote risk assessments for {len(results)} hosts.")


if __name__ == "__main__":
    run()
