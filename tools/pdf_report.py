import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
import weasyprint
from jinja2 import Template

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
from llm_wrapper import use_llm

# Logging Setup
logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler("recon_log.txt", mode="a")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ReconAIssance Report – {{ target }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 30px;
            background: #f4f4f8;
            color: #222;
        }
        h1, h2, h3 {
            color: #005a8d;
            border-bottom: 2px solid #ddd;
            padding-bottom: 6px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ccc;
            font-size: 14px;
        }
        th {
            background-color: #005a8d;
            color: white;
        }
        .critical { background-color: #ffcccc; font-weight: bold; }
        .high { background-color: #ffd699; }
        .medium { background-color: #ffffb3; }
        .low { background-color: #e6ffcc; }
        code, pre {
            font-family: monospace;
            font-size: 13px;
            background: #eef;
            padding: 10px;
            white-space: pre-wrap;
            border: 1px solid #ccc;
        }
        ul {
            margin-left: 20px;
        }
        .section {
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <h1>ReconAIssance Pentest Report</h1>
    <h2>Target: {{ target }}</h2>
    <p><strong>Date:</strong> {{ date }}</p>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>{{ summary }}</p>
    </div>

    <div class="section">
        <h2>Risk Assessment (Top Threats)</h2>
        {{ risk_table | safe }}
    </div>

    <div class="section">
        <h2>Vulnerabilities (CVE Summary)</h2>
        {{ cve_table | safe }}
    </div>

    <div class="section">
        <h2>Exploit Mapping</h2>
        {{ exploit_table | safe }}
    </div>

    <div class="section">
        <h2>Shodan Intelligence</h2>
        {{ shodan_data | safe }}
    </div>

    <div class="section">
        <h2>Reconnaissance Output</h2>
        {{ recon_data | safe }}
    </div>

    <div class="section">
        <h2>Loot Files (Raw Results)</h2>
        {{ loot_data | safe }}
    </div>
</body>
</html>
"""

def build_table(data, fields, severity_field=None):
    html = "<table><tr>" + "".join(f"<th>{f}</th>" for f in fields) + "</tr>"
    for item in data:
        if not isinstance(item, dict):
            logger.warning(f"Ignoring non-dict entry in build_table: {item}")
            continue
        css_class = classify_cvss(item.get(severity_field, "")) if severity_field else ""
        html += "<tr>" + "".join(
            f"<td class='{css_class}'>{item.get(f, '')}</td>" for f in fields
        ) + "</tr>"
    html += "</table>"
    return html

def build_risk_table(run_path):
    path = Path(run_path) / "shodan_ai_risk.json"
    if not path.exists():
        logger.warning("No shodan_ai_risk.json found.")
        return "<p>No risk assessment available.</p>"

    try:
        data = json.load(open(path))
        top = sorted(data, key=lambda x: ["low", "medium", "high", "critical"].index(x["risk"]))[::-1][:3]
        html = "<table><tr><th>IP</th><th>Risk</th><th>Notes</th></tr>"
        for entry in top:
            css = entry["risk"]
            html += f"<tr class='{css}'><td>{entry['ip']}</td><td>{entry['risk']}</td><td>{entry['notes']}</td></tr>"
        html += "</table>"
        return html
    except Exception as e:
        logger.warning(f"Risk table failed: {e}")
        return "<p>Error reading risk data.</p>"

def generate_pdf_report(target, output_dir):
    logger.info(f"Generating PDF report for target: {target}")
    run_path = Path(output_dir)
    cve_data, exploit_data = [], []
    recon_data, shodan_data, loot_data = "", "", ""
    risk_table_html = ""

    # CVE-Daten
    cve_path = run_path / "cve_summary.json"
    if cve_path.exists():
        try:
            cve_data = json.load(open(cve_path))
            logger.info(f"Loaded CVE data ({len(cve_data)} items)")
        except Exception as e:
            logger.warning(f"Failed to load CVE data: {e}")

    # Exploits
    exploit_path = run_path / "cve2exploit_map.json"
    if exploit_path.exists():
        try:
            exploit_data = json.load(open(exploit_path))
            logger.info(f"Loaded exploit mapping ({len(exploit_data)} entries)")
        except Exception as e:
            logger.warning(f"Failed to load exploit mapping: {e}")

    # Recon-Dateien
    for f in run_path.glob("recon_sub_*.txt"):
        try:
            recon_data += f"<h3>{f.name}</h3><pre>{f.read_text()}</pre>"
        except Exception as e:
            logger.warning(f"Failed to read recon file {f.name}: {e}")

    # Shodan
    shodan_path = run_path / "shodan_summary.json"
    if shodan_path.exists():
        try:
            raw = json.load(open(shodan_path))
            shodan_data = f"<pre>{json.dumps(raw, indent=2)}</pre>"
            logger.info("Shodan data loaded")
        except Exception as e:
            logger.warning(f"Failed to load shodan_summary.json: {e}")

    # Risk Table
    risk_table_html = build_risk_table(run_path)

    # Loots
    for f in run_path.glob("*_result.json"):
        try:
            loot_data += f"<h3>{f.name}</h3><pre>{f.read_text()}</pre>"
        except Exception as e:
            logger.warning(f"Failed to read loot file {f.name}: {e}")

    # Executive Summary
    try:
        logger.debug("Calling LLM to generate executive summary...")
        summary_prompt = (
            f"Generate a short summary for a pentest report. CVEs={cve_data}, Exploits={exploit_data[:3]}"
        )
        summary_text = use_llm(task_type="pdf_summary", prompt=summary_prompt)
    except Exception:
        logger.exception("LLM failed to generate summary")
        summary_text = "[!] Summary generation failed."

    try:
        template = Template(HTML_TEMPLATE)
        rendered_html = template.render(
            target=target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            summary=summary_text,
            risk_table=risk_table_html,
            cve_table=build_table(cve_data, ["id", "description", "cvss"], severity_field="cvss"),
            exploit_table=build_table(exploit_data, ["cve", "exploit", "source"]),
            recon_data=recon_data,
            shodan_data=shodan_data,
            loot_data=loot_data
        )
        output_pdf = run_path / f"{target}_report.pdf"
        weasyprint.HTML(string=rendered_html).write_pdf(str(output_pdf))
        logger.info(f"PDF successfully generated at: {output_pdf}")
    except Exception:
        logger.exception("Failed to render and write PDF")
