import os
import json

def run(run_path):
    data = {}
    class_file = os.path.join(run_path, "superscript_class.json")
    if not os.path.exists(class_file):
        print("[!] No classification found.")
        return

    cls = json.load(open(class_file)).get("class", "none")
    data[cls] = data.get(cls, 0) + 1

    html = f"""
    <html>
    <head>
      <title>Superscript Class Chart</title>
      <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
    </head>
    <body>
    <div style='width: 600px; margin: 40px auto;'>
      <h3>Superscript Class Distribution</h3>
      <canvas id='chart'></canvas>
    </div>
    <script>
      const ctx = document.getElementById('chart');
      new Chart(ctx, {{
        type: 'bar',
        data: {{
          labels: {list(data.keys())},
          datasets: [{{
            label: 'Class count',
            data: {list(data.values())},
            backgroundColor: 'rgba(54, 162, 235, 0.7)',
            borderWidth: 1
          }}]
        }},
        options: {{
          scales: {{
            y: {{
              beginAtZero: true
            }}
          }}
        }}
      }});
    </script>
    </body>
    </html>
    """

    with open(os.path.join(run_path, "scriptmind_chart.html"), "w") as f:
        f.write(html)
    print("[✓] Chart generated: scriptmind_chart.html")

if __name__ == "__main__":
    t = os.getenv("RECON_KI_TARGET")
    p = os.getenv("RECON_KI_RUN_PATH")
    if not t or not p:
        exit(1)
    run(p)
