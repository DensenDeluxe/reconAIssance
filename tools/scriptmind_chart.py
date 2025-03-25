import os
import json
import socket
from contextlib import closing


def port_in_use(port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        return sock.connect_ex(('localhost', port)) == 0


def generate_chart(run_path):
    cls_file = os.path.join(run_path, "superscript_class.json")
    if not os.path.exists(cls_file):
        print("[!] No classification found.")
        return

    data = json.load(open(cls_file))
    effect = data.get("effect", "unknown")
    category = data.get("class", "none")
    note = data.get("note", "")

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
    with open(chart_path, "w") as f:
        f.write(html_content)
    print("[✓] Chart generated:", chart_path)

    if not port_in_use(8080):
        os.chdir(run_path)
        os.system("python3 -m http.server 8080 &")
        print("[✓] HTTP Server started on port 8080.")
    else:
        print("[⚠️] HTTP Server on port 8080 already running. Skipping.")


if __name__ == "__main__":
    run_path = os.getenv("RECON_KI_RUN_PATH")
    if not run_path:
        print("[!] Missing RECON_KI_RUN_PATH environment variable.")
        exit(1)

    generate_chart(run_path)
