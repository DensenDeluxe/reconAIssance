import os
import json
import socket
import logging
from contextlib import closing

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

def port_in_use(port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        return sock.connect_ex(('localhost', port)) == 0

def generate_chart(run_path):
    logger.info(f"Generating ScriptMind chart for path: {run_path}")
    cls_file = os.path.join(run_path, "superscript_class.json")
    if not os.path.exists(cls_file):
        logger.warning("No classification file found – skipping chart generation.")
        return

    try:
        data = json.load(open(cls_file))
        effect = data.get("effect", "unknown")
        category = data.get("class", "none")
        note = data.get("note", "")
        logger.debug(f"Loaded classification: effect={effect}, class={category}")
    except Exception as e:
        logger.exception("Failed to read superscript_class.json")
        return

    html_content = f"""
    <html>
    <head>
        <title>ScriptMind Classification Chart</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body style="background-color: #222; color: #eee;">
        <canvas id="scriptmindChart" width="400" height="400"></canvas>
        <script>
            const ctx = document.getElementById('scriptmindChart').getContext('2d');
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: ['Effect', 'Class'],
                    datasets: [{{
                        label: 'ScriptMind Analysis',
                        data: ['{effect}', '{category}'].map(e =>
                            e === 'high' ? 3 :
                            e === 'medium' ? 2 :
                            e === 'low' ? 1 : 0),
                        backgroundColor: [
                            'rgba(75, 192, 192, 0.6)',
                            'rgba(255, 159, 64, 0.6)'
                        ],
                        borderColor: [
                            'rgba(75, 192, 192, 1)',
                            'rgba(255, 159, 64, 1)'
                        ],
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1,
                                callback: (value) => ['none', 'low', 'medium', 'high'][value]
                            }}
                        }}
                    }}
                }}
            }});
        </script>
        <p><b>Note:</b> {note}</p>
    </body>
    </html>
    """

    chart_path = os.path.join(run_path, "scriptmind_chart.html")
    try:
        with open(chart_path, "w") as f:
            f.write(html_content)
        logger.info(f"ScriptMind chart written to: {chart_path}")
    except Exception as e:
        logger.exception("Failed to write chart HTML")

    try:
        if not port_in_use(8080):
            os.chdir(run_path)
            os.system("python3 -m http.server 8080 &")
            logger.info("Started HTTP server on port 8080.")
        else:
            logger.info("HTTP server already running on port 8080.")
    except Exception as e:
        logger.exception("Error starting HTTP server")

if __name__ == "__main__":
    run_path = os.getenv("RECON_KI_RUN_PATH")
    if not run_path:
        logger.error("Missing RECON_KI_RUN_PATH environment variable.")
        exit(1)

    generate_chart(run_path)
