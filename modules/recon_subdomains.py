import os
import subprocess

def build_rc(sub, rc):
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

def scan(sub, path):
    tag = sub.replace(".", "_")
    rc = os.path.join(path, f"recon_sub_{tag}.rc")
    out = os.path.join(path, f"recon_sub_{tag}.txt")
    build_rc(sub, rc)
    try:
        subprocess.run(["msfconsole", "-q", "-r", rc],
                       stdout=open(out, "w"),
                       stderr=subprocess.DEVNULL,
                       text=True,
                       timeout=180)
    except:
        pass

def run(target, path):
    subfile = os.path.join(path, "subdomains.txt")
    if not os.path.exists(subfile):
        return
    with open(subfile, "r") as f:
        subs = [l.strip() for l in f if l.strip()]
    for sub in subs:
        scan(sub, path)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
