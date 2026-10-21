[![SOC Lab Termux](https://img.shields.io/badge/SOC%20Lab-Termux%20%7C%20Android-blue?logo=Android)](https://github.com)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# SOC Lab Termux
Android-based defensive security lab for SOC analyst practice. No cloud, no VPN, no root required.

## What This Is

A working cybersecurity home lab built for Android/Termux. It generates realistic synthetic attack logs, inspects network packets, and produces triage-ready reports — the same core tasks a SOC Tier 1 analyst performs daily.

**Built by:** Kgosi Ntshingila
**Purpose:** Demonstrate hands-on SOC skills without a university degree or expensive training labs.

## Why This Exists

Most people trying to break into cybersecurity can talk about logs, but they've never actually parsed thousands of lines, identified attack patterns, and written findings from them. This repo is the proof.

## What's Inside

- `scripts/log-analysis/apache_analyzer.py` — Detects SQL injection, XSS, path traversal, and shell upload attempts in Apache combined logs
- `scripts/log-analysis/ssh_bruteforce_detector.py` — Identifies brute-force sources, targeted usernames, and successful logins after failures
- `scripts/network-tools/packet_inspector.py` — Parses pcap files with scapy; reports protocol distribution, top talkers, and destination ports
- `scripts/tools/generate_sample_logs.py` — Generates 2,000-line synthetic Apache + Linux auth datasets every run
- `logs/` — Sample attack data for immediate practice
- `install.sh` — One-command Termux setup

## Screenshot of Output

```
=== SSH ANALYSIS RESULTS ===
Failed login attempts: 408
Unique attacking IPs: 4
Successful logins: 79

Top 10 brute force sources:
  192.168.1.100        attempts=114 users=[oracle, postgres, admin, www-data, root]

Successful logins after failures:
  root@203.0.113.5
  postgres@172.16.0.55
```

## Requirements

- Termux (F-Droid recommended)
- Storage permission: `termux-setup-storage`
- Python 3.8+
- Packages: `nmap`, `tcpdump`, `tshark`, `scapy`, `requests`, `python-nmap`, `yara-python`

## 60-Second Setup

```bash
git clone https://github.com/kingswr1d/soc-lab-termux.git
cd soc-lab-termux
bash install.sh
python3 scripts/tools/generate_sample_logs.py
python3 scripts/log-analysis/ssh_bruteforce_detector.py logs/linux_auth.log
python3 scripts/log-analysis/apache_analyzer.py logs/apache_access.log
```

## What Each Script Does

### apache_analyzer.py

Reads Apache Combined log format. Extracts source IP, HTTP method, request path, status code, and response size. Scans every request for attack signatures:

- SQLi: `UNION`, `SELECT`, `DROP`, `--`, single-quote
- XSS: `<script>`, `javascript:`, `onerror=`
- Path traversal: `../` sequences
- Web shell uploads: `.php`/`.asp`/`.jsp` combined with `/upload`

Outputs: top attacker IPs, status distribution, pattern counts.

### ssh_bruteforce_detector.py

Matches syslog-style auth lines:

- `Failed password for <user> from <ip> port <port> ssh2`
- `Accepted password for <user> from <ip> port <port> ssh2`

Maps IPs to targeted usernames, flags successful logins after repeated failures, and identifies credential stuffing patterns.

### packet_inspector.py

Uses `scapy.rdpcap()` to read a pcap, then tallies:
- Protocol class frequency (`Ether`, `IP`, `TCP`, `UDP`, `DNS`, etc.)
- Top source and destination IPs by packet count
- Top destination ports by connection count

Useful for spotting C2 beacons, port scans, and exfiltration endpoints.

## Sample Analysis Report

Every run of these scripts produces structured output you can drop straight into an incident ticket or client report. Example finding format:

```
FINDING: Multiple successful SSH logins after repeated failures
SEVERITY: High
SOURCE_IP: 203.0.113.5
USERNAMES_TARGETED: root, admin, www-data
SUCCESSFUL_LOGONS: 3
RECOMMENDATION: Block source IP at perimeter, rotate affected credentials, enforce key-based auth.
```

## Project Status

- [x] Lab environment documented
- [x] Log analyzer scripts
- [x] Brute-force detector
- [x] Synthetic data generator
- [x] Network packet inspector
- [x] Packaged for Termux on Android
- [ ] PortSwringer lab writeups added
- [ ] TryHackMe SOC Level 1 completion certificate
- [ ] CompTIA Security+ exam scheduled (5 November 2026)
- [x] CompTIA CCNA exam passed (July 2026)
- [ ] AWS cloud practitioner exam scheduled

## Skills Demonstrated

- Python script development
- Regular expression pattern matching
- Log source analysis (Apache, Linux auth)
- Network packet inspection
- Defensive detection engineering
- Technical documentation
- Privacy/compliance framing (POPIA-ready SA context)

## Roadmap for This Repo

1. Add TryHackMe and PortSwigger lab writeups
2. Add custom YARA rules for log-based detection
3. Add a JSON alerting pipeline (script → jq filter → report)
4. Add a small REST API wrapper around analyzers so they can be called remotely

## License

MIT
