#!/bin/bash

# Set up venv
echo "[+] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python packages
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

# System-level dependencies for weasyprint & playwright
echo "[+] Installing system dependencies (Ubuntu)..."
sudo apt update
sudo apt install -y libpango-1.0-0 libgdk-pixbuf2.0-0 libffi-dev libcairo2 fonts-liberation libnss3 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 libxrandr2 libasound2 libatk1.0-0 libatk-bridge2.0-0 libxss1 libgbm1 libxshmfence1 libxinerama1 libpangoft2-1.0-0 libgtk-3-0

# Playwright setup
echo "[+] Installing playwright browsers..."
playwright install

# Optional CLI tools (manual if not present)
echo "[+] Checking optional tools (subfinder, amass, crunch, hashcat)"
which subfinder || echo "[-] subfinder missing"
which amass || echo "[-] amass missing"
which crunch || echo "[-] crunch missing"
which hashcat || echo "[-] hashcat missing"

# Reminder
echo "[✓] Setup complete. To activate: source venv/bin/activate"
echo "[!] Ensure you add your HuggingFace token to tools/apitoken.txt"
echo "[!] Optional: tools/github_token.txt for GitHub OSINT"