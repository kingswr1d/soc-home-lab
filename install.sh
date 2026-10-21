#!/usr/bin/env bash
# SOC home lab setup for a Linux desktop (Debian / Ubuntu / Kali / Mint).
# Run from the repo root:  bash install.sh
#
# - installs the command-line tools the lab uses (asks for sudo once)
# - creates a Python virtual environment in .venv with scapy
# - generates the sample logs and pcap into ./logs
set -e
cd "$(dirname "$0")"

echo "=== SOC home lab setup ==="

if command -v apt-get >/dev/null 2>&1; then
  echo "[1/4] Installing system packages (sudo)"
  sudo apt-get update -qq
  sudo apt-get install -y python3 python3-venv python3-pip jq tcpdump tshark nmap whois dnsutils
else
  echo "[1/4] No apt-get found -- install python3, python3-venv, jq, tshark, tcpdump, nmap yourself."
fi

echo "[2/4] Creating Python virtual environment in .venv"
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q scapy

echo "[3/4] Generating sample logs + pcap into ./logs"
.venv/bin/python scripts/tools/generate_sample_logs.py
.venv/bin/python scripts/tools/generate_sample_pcap.py

echo "[4/4] Smoke test"
.venv/bin/python scripts/log-analysis/ssh_bruteforce_detector.py logs/linux_auth.log >/dev/null || [ $? -le 2 ]
.venv/bin/python scripts/log-analysis/apache_analyzer.py logs/apache_access.log >/dev/null || [ $? -le 2 ]
.venv/bin/python scripts/network-tools/packet_inspector.py logs/sample.pcap >/dev/null || [ $? -le 2 ]

echo
echo "Done. Activate the environment, then run the detectors:"
echo "  source .venv/bin/activate"
echo "  python scripts/log-analysis/ssh_bruteforce_detector.py logs/linux_auth.log"
echo "  python scripts/log-analysis/apache_analyzer.py logs/apache_access.log"
echo "  python scripts/network-tools/packet_inspector.py logs/sample.pcap"
echo
echo "On your own machine:"
echo "  sudo .venv/bin/python scripts/log-analysis/ssh_bruteforce_detector.py /var/log/auth.log"
echo "  sudo tcpdump -i any -w capture.pcap   # then run packet_inspector.py on it"
