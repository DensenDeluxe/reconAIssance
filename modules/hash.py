import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))

def find_sources(path):
    files = []
    for root, _, fs in os.walk(path):
        for f in fs:
            if f.lower() in ["shadow", ".htpasswd", "passwd", "sam"]:
                files.append(os.path.join(root, f))
    return files

def extract(lines):
    h = []
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) > 1 and parts[1].startswith("$"):
            h.append(parts[1])
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
    files = find_sources(path)
    hashes = []
    for f in files:
        with open(f, "r", errors="ignore") as fx:
            hashes += extract(fx.readlines())
    if not hashes:
        return
    out = os.path.join(path, "hashes.txt")
    with open(out, "w") as f:
        for h in hashes:
            f.write(h + "\n")
    mode, label = guess_mode(hashes[0])
    cmd = f"hashcat -a 0 -m {mode} {out} rockyou.txt --force"
    with open(os.path.join(path, "hashcat_command.txt"), "w") as f:
        f.write(cmd + "\n")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
