import os
import sys
import re
import json
import weasyprint
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_wrapper import use_llm

    TEMPLATE = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>ReconAIssance Report</title>
    <style>
        body {{ background-color: #111; color: #ddd; font-family: 'Courier New', monospace; padding: 2em; }}
        h1, h2, h3 {{ color: #4caf50; border-bottom: 1px solid #444; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1em 0; }}
        th, td {{ border: 1px solid #555; padding: 0.5em; }}
        th {{ background-color: #222; color: #fff; }}
        td.critical {{ background-color: #b71c1c; color: #fff; font-weight: bold; }}
        td.high {{ background-color: #f57c00; color: #fff; }}
        td.medium {{ background-color: #fbc02d; color: #000; }}
        td.low {{ background-color: #388e3c; color: #fff; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
        footer {{ text-align: center; margin-top: 4em; font-size: 0.8em; color: #888; }}
    </style>
    </head>
    <body>
    <h1>ReconAIssance Intelligence & Exploitation Summary</h1>
    <p><b>Target:</b> {target}</p>
    <p><b>Run Date:</b> {date}</p>

    <h2>Executive Summary</h2>
    <p>{summary}</p>

    <h2>Discovered CVEs</h2>
    {cve_table}

    <h2>Exploit Results</h2>
    {exploit_table}

    <h2>Recon & OSINT</h2>
    {recon_data}

    <h2>Shodan Exposure</h2>
    {shodan_data}

    <h2>Post-Exploitation Findings</h2>
    {loot_data}

    <footer>CONFIDENTIAL | Authorized Personnel Only</footer>
    </body>
    </html>
    """


def classify_cvss(score):
    try:
        s = float(score)
        if s >= 9: return "critical"
        if s >= 7: return "high"
        if s >= 4: return "medium"
        return "low"
    except:
        return "low"

def render_cve_table(cves):
    if not cves:
        return "<p>No CVEs detected.</p>"
    rows = "".join(
        f"<tr><td>{cve}</td><td class='{classify_cvss(data.get('score', ''))}'>{data.get('score', '')}</td>"
        f"<td>{data.get('severity', '')}</td><td>{data.get('llm_analysis', '')[:200]}</td></tr>"
        for cve, data in cves.items()
    )
    return f"<table><thead><tr><th>ID</th><th>Score</th><th>Severity</th><th>AI Summary</th></tr></thead><tbody>{rows}</tbody></table>"

def render_exploit_table(results):
    if not results:
        return "<p>No exploits triggered.</p>"
    rows = "".join(
        f"<tr><td>{m}</td><td>{'✅' if m in results.get('modules_valid', []) else '❌'}</td></tr>"
        for m in results.get("modules_checked", [])
    )
    return f"<table><thead><tr><th>Module</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>"

def render_recon(path):
    parts = []
    for name in ["recon.txt", "subdomains.txt", "staff.txt"]:
        f = os.path.join(path, name)
        if os.path.exists(f):
            content = open(f, encoding="utf-8", errors="ignore").read()[:3000]
            parts.append(f"<h3>{name}</h3><pre>{content}</pre>")
    return "".join(parts)

def render_loot(path):
    for name in ["meterpreter.txt", "ssh_post_chain_root.log"]:
        f = os.path.join(path, name)
        if os.path.exists(f):
            content = open(f, encoding="utf-8", errors="ignore").read()[:4000]
            return f"<pre>{content}</pre>"
    return "<p>No loot found.</p>"

def render_shodan(path):
    file = os.path.join(path, "shodan_summary.json")
    if not os.path.exists(file):
        return "<p>No Shodan data available.</p>"
    data = json.load(open(file))
    html = []
    for ip, entry in data.items():
        analysis = entry.get('llm_analysis', 'no analysis')
        html.append(f"<h3>{ip}</h3><pre>{analysis}</pre>")
    return "".join(html)

def generate_pdf_report(target, run_path):
    cve_file = os.path.join(run_path, "cve_summary.json")
    exp_file = os.path.join(run_path, "exploit_result.json")
    cves = json.load(open(cve_file)) if os.path.exists(cve_file) else {}
    exploits = json.load(open(exp_file)) if os.path.exists(exp_file) else {}

    summary_prompt = f"""Provide a concise high-level summary for target {target} with {len(cves)} CVEs discovered.
ONLY RETURN VALID JSON. Example:
{{"summary": "Concise summary text..."}}
"""

    summary_response = use_llm("summary_report", summary_prompt)
    try:
        summary_json = json.loads(summary_response.strip().split("\n")[-1])
        summary = summary_json.get("summary", "No summary provided.")
    except json.JSONDecodeError:
        summary = f"LLM parse error: {summary_response[:200]}"

    html = TEMPLATE.format(
        target=target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        summary=summary,
        cve_table=render_cve_table(cves),
        exploit_table=render_exploit_table(exploits),
        recon_data=render_recon(run_path),
        shodan_data=render_shodan(run_path),
        loot_data=render_loot(run_path)
)


    pdf_filename = f"{re.sub(r'[^a-zA-Z0-9_.-]', '_', target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path = os.path.join(get_desktop(), pdf_filename)
    weasyprint.HTML(string=html).write_pdf(pdf_path)

    print(f"[📄] PDF Report saved: {pdf_path}")

def get_desktop():
    try:
        d = os.popen("xdg-user-dir DESKTOP").read().strip()
        if os.path.isdir(d):
            return d
    except:
        pass
    return os.path.join(Path.home(), "Desktop")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        print("[!] Missing environment variables.")
        exit(1)
    generate_pdf_report(t, p)
