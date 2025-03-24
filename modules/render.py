import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "tools")))
import json
from datetime import datetime

def scriptmind_section(path):
    html = []
    s = next((f for f in os.listdir(path) if f.startswith("superscript_") and f.endswith(".user.js")), None)
    if s:
        html.append(f"<p><b>Superscript:</b> <a href='{s}' target='_blank'>{s}</a></p>")

    impact = os.path.join(path, "superscript_impact.txt")
    if os.path.exists(impact):
        with open(impact) as f:
            html.append("<ul>" + "".join(f"<li>{l.strip()}</li>" for l in f.readlines()) + "</ul>")

    cls = os.path.join(path, "superscript_class.json")
    if os.path.exists(cls):
        mods = json.load(open(cls)).get("module", [])
        if mods:
            html.append("<p><b>Modules:</b></p><ul>")
            html += [f"<li>{m}</li>" for m in mods]
            html.append("</ul>")

    cve = os.path.join(path, "superscript_cve_matches.json")
    if os.path.exists(cve):
        matches = json.load(open(cve))
        html.append("<p><b>Linked CVEs:</b></p><ul>")
        html += [f"<li><a href='https://www.exploit-db.com/search?q={c}' target='_blank'>{c}</a></li>" for c in matches]
        html.append("</ul>")

    rank = os.path.join(path, "scriptmind_ranking.html")
    if os.path.exists(rank):
        html.append(f"<p><a href='scriptmind_ranking.html' target='_blank'>Ranking</a></p>")

    return "".join(html)

def render(cves, path):
    html = [f"""
<html>
<head>
  <meta charset='utf-8'>
  <title>ReconAIssance Report</title>
  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
  <style>
    body {{ background-color: #f8f9fa; }}
    table {{ background-color: #ffffff; }}
    th {{ background-color: #343a40; color: #ffffff; }}
  </style>
</head>
<body>
<div class='container mt-4'>
  <h1>ReconAIssance Report</h1>
  <p><b>Timestamp:</b> {datetime.now()}</p>
  <h2>CVEs</h2>
  <table class='table table-bordered'>
    <thead>
      <tr>
        <th>ID</th>
        <th>Score</th>
        <th>Severity</th>
        <th>ExploitDB</th>
        <th>AI Analysis</th>
      </tr>
    </thead>
    <tbody>
"""]

    for cve_id, entry in cves.items():
        score = entry.get("score", "n/a")
        sev = entry.get("severity", "n/a").upper()
        ai = entry.get("llm_analysis", "")
        link = f"https://www.exploit-db.com/search?q={cve_id}" if cve_id.startswith("CVE") else "#"
        html.append(f"<tr><td>{cve_id}</td><td>{score}</td><td>{sev}</td><td><a href='{link}' target='_blank'>EDB</a></td><td>{ai}</td></tr>")

    html.append("""
    </tbody>
  </table>
""")

    html.append(scriptmind_section(path))

    html.append("""
</div>
</body>
</html>
""")

    with open(os.path.join(path, "cve_report.html"), "w") as f:
        f.write("".join(html))

def run(target, path):
    f = os.path.join(path, "cve_summary.json")
    if not os.path.exists(f):
        return
    cve = json.load(open(f))
    render(cve, path)

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(t, p)
