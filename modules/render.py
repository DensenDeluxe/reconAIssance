import os
import sys
import json
import logging
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))

# Setup logger
logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler = logging.FileHandler("recon_log.txt", mode='w')
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

def scriptmind_section(path):
    html = []
    try:
        s = next((f for f in os.listdir(path) if f.startswith("superscript_") and f.endswith(".user.js")), None)
        if s:
            html.append(f"<p><b>Superscript:</b> <a href='{s}' target='_blank'>{s}</a></p>")
        impact = os.path.join(path, "superscript_impact.txt")
        if os.path.exists(impact):
            with open(impact) as f:
                html.append("<ul>" + "".join(f"<li>{l.strip()}</li>" for l in f.readlines()) + "</ul>")
        cls = os.path.join(path, "superscript_class.json")
        if os.path.exists(cls):
            with open(cls) as f:
                mods = json.load(f).get("module", [])
            if mods:
                html.append("<p><b>Modules:</b></p><ul>")
                for mod in mods:
                    name = mod.get("name", "Unknown")
                    description = mod.get("description", "No description available.")
                    html.append(f"<li><b>{name}</b>: {description}</li>")
                html.append("</ul>")
    except Exception as e:
        logger.exception("Error generating ScriptMind section")
    return "\n".join(html)

def generate_pdf_report(target, data_path, output_path):
    from jinja2 import Environment, FileSystemLoader
    from weasyprint import HTML

    logger.info(f"Starting PDF report generation for target: {target}")

    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')

    def load_json(filename):
        filepath = os.path.join(data_path, filename)
        if os.path.exists(filepath):
            try:
                with open(filepath) as f:
                    logger.debug(f"Loading file: {filename}")
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load {filename}: {e}")
        else:
            logger.warning(f"File not found: {filename}")
        return {}

    cve_summary = load_json('cve_summary.json')
    exploit_result = load_json('exploit_result.json')
    brute_result = load_json('brute_fallback_result.json')
    shodan_summary = load_json('shodan_summary.json')
    staff = load_json('staff.json')

    def safe_get(data, key, default):
        return data.get(key, default) if isinstance(data, dict) else default

    def safe_list(data, key=None):
        if key:
            return data.get(key, []) if isinstance(data, dict) and isinstance(data.get(key), list) else []
        return data if isinstance(data, list) else []

    modules_valid = safe_list(exploit_result, 'modules_valid')
    top_exploits = modules_valid[:3]
    logger.debug(f"Top exploits: {top_exploits}")

    brute_attempts = safe_list(brute_result)