import os
import sys
import subprocess
import ipaddress

def extract_ip(log_path):
    try:
        with open(log_path, "r") as f:
            lines = f.readlines()
        for line in lines:
            if "inet " in line and "127." not in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[1].split("/")[0]
                    return ip
    except:
        return None
    return None

def run_lateral_scan(my_ip, run_path):
    base = ipaddress.IPv4Interface(f"{my_ip}/24").network
    targets = [str(ip) for ip in base.hosts() if str(ip) != my_ip]
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
            except Exception as e:
                f.write(f"{ip}: error {e}\n")

def run(target, run_path):
    log_file = os.path.join(run_path, "meterpreter.txt")
    if not os.path.exists(log_file):
        return
    ip = extract_ip(log_file)
    if not ip:
        return
    run_lateral_scan(ip, run_path)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
