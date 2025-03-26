import json
import os
import subprocess
from query_splitter import generate_query_splits
from batch_lookup import run_batch_lookup
from shodan_db_ai import run as run_ai_risk
from pathlib import Path

def full_chain(goal, auto_start=True):
    print(f"\n🔍 Splitting query for: {goal}")
    queries = generate_query_splits(goal)
    if not queries:
        print("❌ No queries generated.")
        return

    print(f"🧠 {len(queries)} queries generated.")
    run_batch_lookup(queries)

    print("\n🤖 Running AI-based risk analysis...")
    run_ai_risk()

    if auto_start:
        print("\n🚀 Launching reconAIssance on critical hosts...")
        subprocess.run(["python3", "reconAIssance.py"])
    else:
        print("✅ Done. You may now run reconAIssance.py manually.")


def interactive():
    print("🎯 Smart Recon Chain")
    goal = input("Recon Goal (e.g. webcams in France): ").strip()
    full_chain(goal)

if __name__ == "__main__":
    interactive()
