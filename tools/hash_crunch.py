import os
import json
import subprocess
from pathlib import Path
from llm_wrapper import use_llm
from hash import find_sources, extract, guess_mode
from datetime import datetime

def load_usernames(run_path):
    brute_file = os.path.join(run_path, "ssh_brute_result.json")
    if os.path.exists(brute_file):
        try:
            results = json.load(open(brute_file))
            return list(set(r['user'] for r in results if 'user' in r))
        except:
            pass
    return ["root"]

def infer_crunch_args(target, usernames, hash_sample):
    prompt = f"""You are a password cracking strategist.
Given the following:
- Target: {target}
- Usernames: {', '.join(usernames)}
- Hash sample: {hash_sample}
Suggest optimized crunch arguments.

Return JSON:
{{
  "min_length": ..., 
  "max_length": ..., 
  "charset": "...", 
  "notes": "...",
  "example_pw": ["..."]
}}
"""
    result = use_llm("crunch_args", prompt)
    try:
        return json.loads(result.split("\n")[-1])
    except:
        return {
            "min_length": 6,
            "max_length": 12,
            "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
            "notes": "Fallback default",
            "example_pw": []
        }

def build_crunch_pipe(run_path, args, mode):
    fifo = os.path.join(run_path, "crunchpipe")
    try:
        os.mkfifo(fifo)
    except FileExistsError:
        pass

    log = os.path.join(run_path, "hashcat_crack.log")
    hashes = os.path.join(run_path, "hashes.txt")

    crunch_cmd = [
        "crunch", str(args["min_length"]), str(args["max_length"]), args["charset"]
    ]
    hashcat_cmd = [
        "hashcat", "-a", "0", "-m", mode, hashes, fifo, "--force", "--status"
    ]

    with open(os.path.join(run_path, "crunch_args.json"), "w") as f:
        json.dump(args, f, indent=2)

    with open(log, "w") as logfile:
        subprocess.Popen(crunch_cmd, stdout=open(fifo, "w"), stderr=logfile)
        subprocess.run(hashcat_cmd, stdout=logfile, stderr=subprocess.STDOUT)

    print(f"[✓] Crunch-based cracking complete. See {log}")

def fallback_pw_list(run_path, mode):
    pw_dir = Path("PW")
    if not pw_dir.exists(): return
    hashes = os.path.join(run_path, "hashes.txt")
    log = os.path.join(run_path, "hashcat_fallback.log")
    for pwfile in pw_dir.glob("*.txt"):
        print(f"[*] Fallback with: {pwfile.name}")
        subprocess.run([
            "hashcat", "-a", "0", "-m", mode, hashes, str(pwfile), "--force", "--status"
        ], stdout=open(log, "a"), stderr=subprocess.STDOUT)

def run(target, run_path):
    files = find_sources(run_path)
    if not files:
        print("[!] No hash files found.")
        return

    hashes = []
    for f in files:
        with open(f, "r", errors="ignore") as fx:
            hashes += extract(fx.readlines())
    if not hashes:
        print("[!] No hashes extracted.")
        return

    out = os.path.join(run_path, "hashes.txt")
    with open(out, "w") as f:
        for h in hashes:
            f.write(h + "\n")

    mode, label = guess_mode(hashes[0])
    usernames = load_usernames(run_path)
    args = infer_crunch_args(target, usernames, hashes[0])
    build_crunch_pipe(run_path, args, mode)
    fallback_pw_list(run_path, mode)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
