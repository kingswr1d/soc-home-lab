#!/usr/bin/env bash
# SOC Lab setup -- Termux (Android) or Debian/Ubuntu.
# Run from the repo root:  bash install.sh
set -e
cd "$(dirname "$0")"

echo "=== SOC Lab Setup ==="

if command -v pkg >/dev/null 2>&1 && [ -n "$PREFIX" ]; then
  echo "[1/4] Termux detected -- installing packages"
  pkg update -y
  pkg install -y python git curl jq tcpdump tshark nmap openssl dnsutils whois
else
  echo "[1/4] Not Termux -- skipping system packages."
  echo "      On Debian/Ubuntu: sudo apt install python3-venv tshark tcpdump nmap jq"
fi

echo "[2/4] Installing Python libraries (scapy for packet_inspector.py)"
python3 -m pip install --upgrade scapy || echo "      scapy install failed; log analyzers still work (stdlib only)"

echo "[3/4] Generating sample logs + pcap into ./logs"
python3 scripts/tools/generate_sample_logs.py
python3 scripts/tools/generate_sample_pcap.py || echo "      (pcap skipped -- needs scapy)"

echo "[4/4] Smoke test"
python3 scripts/log-analysis/ssh_bruteforce_detector.py logs/linux_auth.log >/dev/null || [ $? -le 2 ]
python3 scripts/log-analysis/apache_analyzer.py logs/apache_access.log >/dev/null || [ $? -le 2 ]

echo
echo "Done. Try:"
echo "  python3 scripts/log-analysis/ssh_bruteforce_detector.py logs/linux_auth.log"
echo "  python3 scripts/log-analysis/apache_analyzer.py logs/apache_access.log"
echo "  python3 scripts/network-tools/packet_inspector.py logs/sample.pcap"
