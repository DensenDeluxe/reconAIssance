import os
import markdown
import weasyprint
import json
from llm_wrapper import use_llm
from datetime import datetime

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ReconAIssance Report</title>
  <style>
    body { font-family: monospace; background: #111; color: #ddd; padding: 2em; }
    h1, h2, h3 { color: #4caf50; border-bottom: 1px solid #444; }
    table { border-collapse: collapse; width: 100%; margin: 1em 0; }
    th, td { border: 1px solid #555; padding: 0.5em; }
    th { background: #222; color: #fff; }
    td.critical { background: #b71c1c; color: #fff; font-weight: bold; }
    td.high     { background: #f57c00; color: #fff; }
    td.medium   { background: #fbc02d; color: #000; }
    td.low      { background: #388e3c; color: #fff; }
    footer { text-align: center; margin-top: 4em; font-size: 0.8em; color: #888; }
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
    if not cves: return "<p>No CVEs detected.</p>"
    rows = "".join(
        f"<tr><td>{cve}</td><td class='{classify_cvss(data.get('score', ''))}'>{data.get('score', '')}</td>"
        f"<td>{data.get('severity', '')}</td><td>{data.get('llm_analysis', '')[:200]}</td></tr>"
        for cve, data in cves.items()
    )
    return f"<table><thead><tr><th>ID</th><th>Score</th><th>Severity</th><th>AI Summary</th></tr></thead><tbody>{rows}</tbody></table>"

def render_exploit_table(results):
    if not results: return "<p>No exploits triggered.</p>"
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
            parts.append(f"<h3>{name}</h3><pre>{open(f).read()[:3000]}</pre>")
    return "".join(parts)

def render_loot(path):
    for name in ["meterpreter.txt", "ssh_post_chain_root.log"]:
        f = os.path.join(path, name)
        if os.path.exists(f):
            return f"<pre>{open(f).read()[:4000]}</pre>"
    return "<p>No loot found.</p>"

def generate_pdf_report(target, run_path):
    cve_file = os.path.join(run_path, "cve_summary.json")
    exp_file = os.path.join(run_path, "exploit_result.json")
    cves = json.load(open(cve_file)) if os.path.exists(cve_file) else {}
    exploits = json.load(open(exp_file)) if os.path.exists(exp_file) else {}

    summary_prompt = f"Give a concise, high-level summary of this scan against {target}. Found {len(cves)} CVEs."
    summary = use_llm("summary_report", summary_prompt)

    html = TEMPLATE.format(
        target=target,
        date=datetime.now(),
        summary=summary,
        cve_table=render_cve_table(cves),
        exploit_table=render_exploit_table(exploits),
        recon_data=render_recon(run_path),
        loot_data=render_loot(run_path)
    )

    pdf_path = os.path.join(get_desktop(), f"ReconAIssance_{re.sub(r'[^a-zA-Z0-9_.-]', '_', target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
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
        exit(1)
    generate_pdf_report(t, p)
