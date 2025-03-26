import json
import re
from pathlib import Path

DB_FILE = Path("loot/shodan_db.jsonl")


def search_db(keyword=None, port=None, cpe=None):
    if not DB_FILE.exists():
        print("❌ Database file not found.")
        return []

    results = []
    with open(DB_FILE) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            match = True
            if keyword:
                match &= keyword.lower() in json.dumps(entry).lower()
            if port:
                match &= port in entry.get("ports", [])
            if cpe:
                cpes = []
                for s in entry.get("data", []):
                    cpes.extend(s.get("cpe", []))
                match &= any(cpe in x for x in cpes)

            if match:
                results.append(entry)

    return results


def interactive():
    print("🔎 Search Shodan DB")
    keyword = input("Keyword (IP, org, ASN, etc.): ").strip() or None
    port = input("Port (e.g. 22): ").strip()
    port = int(port) if port.isdigit() else None
    cpe = input("CPE (e.g. cpe:/a:nginx:nginx): ").strip() or None

    matches = search_db(keyword=keyword, port=port, cpe=cpe)
    print(f"\n✅ {len(matches)} matching host(s):")
    for m in matches:
        print(f"- {m.get('ip_str')} | {m.get('org')} | Ports: {m.get('ports')} | {m.get('location')}")


if __name__ == "__main__":
    interactive()
