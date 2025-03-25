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
        if s >= 9:
            return "critical"
        if s >= 7:
            return "high"
        if s >= 4:
            return "medium"
        return "low"
    except:
        return ""

def build_table(data, fields, severity_field=None):
    html = "<table><tr>" + "".join(f"<th>{f}</th>" for f in fields) + "</tr>"
    for item in data:
        css_class = classify_cvss(item.get(severity_field, "")) if severity_field else ""
        html += "<tr>" + "".join(
            f"<td class='{css_class}'>{item.get(f, '')}</td>" for f in fields
        ) + "</tr>"
    html += "</table>"
    return html

def generate_pdf_report(target, output_dir):
    run_path = Path(output_dir)
    cve_data = []
    exploit_data = []
    recon_data = ""
    shodan_data = ""
    loot_data = ""

    # Load CVE data
    cve_path = run_path / "cve_summary.json"
    if cve_path.exists():
        with open(cve_path) as f:
            cve_data = json.load(f)

    # Load Exploit Mapping
    exploit_path = run_path / "cve2exploit_map.json"
    if exploit_path.exists():
        with open(exploit_path) as f:
            exploit_data = json.load(f)

    # Load Recon Results
    for f in run_path.glob("recon_sub_*.txt"):
        with open(f) as rf:
            recon_data += f"<h3>{f.name}</h3><pre>{rf.read()}</pre>"

    # Load Shodan Summary
    shodan_path = run_path / "shodan_summary.json"
    if shodan_path.exists():
        with open(shodan_path) as f:
            shodan = json.load(f)
            shodan_data = f"<pre>{json.dumps(shodan, indent=2)}</pre>"

    # Load Loot (fallback brute, hashes, etc.)
    for f in run_path.glob("*_result.json"):
        with open(f) as lf:
            loot_data += f"<h3>{f.name}</h3><pre>{lf.read()}</pre>"

    summary_text = use_llm(
        f"Generate a short summary for a PDF report of the following CVEs and exploits: CVEs={cve_data}, Exploits={exploit_data[:3]}"
    )

    html = TEMPLATE.format(
        target=target,
        date=str(datetime.now()),
        summary=summary_text,
        cve_table=build_table(cve_data, ["id", "description", "cvss"], severity_field="cvss"),
        exploit_table=build_table(exploit_data, ["cve", "exploit", "source"]),
        recon_data=recon_data,
        shodan_data=shodan_data,
        loot_data=loot_data
    )

    output_pdf = run_path / f"{target}_report.pdf"
    weasyprint.HTML(string=html).write_pdf(str(output_pdf))
    print(f"[✓] PDF generated at: {output_pdf}")
