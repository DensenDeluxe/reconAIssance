#!/bin/bash

set -e

echo "[+] Setting up ReconAIssance virtual environment..."

# Create venv
if [ ! -d "venv" ]; then
  python3 -m venv venv
fi
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright binaries
playwright install chromium

# System packages
echo "[+] Installing required system packages..."
sudo apt update
sudo apt install -y \
  sshpass netcat curl git unzip build-essential \
  libffi-dev libssl-dev libxml2-dev libxslt1-dev \
  crunch hashcat \
  subfinder amass \
  ocl-icd-libopencl1 nvidia-cuda-toolkit

# Install Metasploit (if not present)
if ! command -v msfconsole &> /dev/null; then
  echo "[+] Installing Metasploit..."
  curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall > msfinstall
  chmod +x msfinstall && sudo ./msfinstall && rm msfinstall
fi

# Ensure PW folder + rockyou.txt
mkdir -p PW
if [ ! -f PW/rockyou.txt ]; then
  echo "[+] Downloading rockyou.txt into PW/..."
  wget -O PW/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
fi

# Ensure UN folder + best usernames
mkdir -p UN
if [ ! -f UN/top-usernames.txt ]; then
  echo "[+] Downloading top-usernames.txt into UN/..."
  wget -O UN/top-usernames.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
fi

# Make all scripts executable
chmod +x reconAIssance.py
chmod +x modules/*.py tools/*.py

echo "[✓] Installation complete."
echo ""
echo "[→] To start recon:"
echo "source venv/bin/activate && python3 reconAIssance.py"
