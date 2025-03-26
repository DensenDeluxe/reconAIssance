import os
import sys
import re
import json
import logging
import weasyprint
from datetime import datetime
from pathlib import Path

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

TEMPLATE = """<html>... (gekürzt) ...</html>"""  # Unverändert gelassen zur Übersicht

def classify_cvss(score):
    try:
        s = float(score)
        if s >= 9: return "critical"
        if s >= 7: return "high"
        if s >= 4: return "medium"
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
    logger.info(f"Generating PDF report for target: {target}")
    run_path = Path(output_dir)
    cve_data, exploit_data = [], []
    recon_data, shodan_data, loot_data = "", "", ""

    # Load CVE data
    cve_path = run_path / "cve_summary.json"
    if cve_path.exists():
        try:
            with open(cve_path) as f:
                cve_data = json.load(f)
            logger.info(f"Loaded CVE data ({len(cve_data)} items)")
        except Exception as e:
            logger.warning(f"Failed to load CVE data: {e}")

    # Load Exploit Mapping
    exploit_path = run_path / "cve2exploit_map.json"
    if exploit_path.exists():
        try:
            with open(exploit_path) as f:
                exploit_data = json.load(f)
            logger.info(f"Loaded exploit mapping ({len(exploit_data)} entries)")
        except Exception as e:
            logger.warning(f"Failed to load exploit mapping: {e}")

    # Load Recon Results
    for f in run_path.glob("recon_sub_*.txt"):
        try:
            with open(f) as rf:
                recon_data += f"<h3>{f.name}</h3><pre>{rf.read()}</pre>"
        except Exception as e:
            logger.warning(f"Failed to read recon file {f.name}: {e}")

    # Load Shodan Summary
    shodan_path = run_path / "shodan_summary.json"
    if shodan_path.exists():
        try:
            with open(shodan_path) as f:
                shodan = json.load(f)
                shodan_data = f"<pre>{json.dumps(shodan, indent=2)}</pre>"
            logger.info("Shodan data loaded")
        except Exception as e:
            logger.warning(f"Failed to load shodan_summary.json: {e}")

    # Load Loot (fallback brute, hashes, etc.)
    for f in run_path.glob("*_result.json"):
        try:
            with open(f) as lf:
                loot_data += f"<h3>{f.name}</h3><pre>{lf.read()}</pre>"
        except Exception as e:
            logger.warning(f"Failed to read loot file {f.name}: {e}")

    try:
        logger.debug("Calling LLM to generate executive summary...")
        summary_text = use_llm(
            f"Generate a short summary for a PDF report of the following CVEs and exploits: CVEs={cve_data}, Exploits={exploit_data[:3]}"
        )
    except Exception as e:
        logger.exception("LLM failed to generate summary")
        summary_text = "[!] Summary generation failed."

    try:
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
        logger.info(f"PDF successfully generated at: {output_pdf}")
    except Exception as e:
        logger.exception("Failed to generate PDF")
