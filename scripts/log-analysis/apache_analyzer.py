#!/usr/bin/env python3
"""
Apache access-log analyzer (Common or Combined Log Format).

Request paths are URL-decoded before matching, because attackers' payloads
arrive encoded (e.g. %27 for ', %3Cscript%3E for <script>).

Detects:
  - SQL injection     (UNION SELECT, ' OR '1'='1, SLEEP(), information_schema, ...)
  - XSS               (<script>, onerror=, onload=, javascript:)
  - Path traversal    (../ and encoded variants, /etc/passwd)
  - Recon / scanning  (.env, .git, wp-login, phpmyadmin, backups)
  - Web shell use     (?cmd= / ?exec= on a .php/.jsp/.asp file)
  - Known attack tools by User-Agent (sqlmap, nikto, nmap, ...)

Usage:
  python3 apache_analyzer.py /var/log/apache2/access.log
"""
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import unquote_plus

LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.+?) (?P<proto>HTTP/[\d.]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

RULES = {
    "SQL injection": re.compile(
        r"union(\s|/\*.*?\*/)+(all\s+)?select|'\s*or\s*'?\d*'?\s*=\s*'?\d|"
        r"\bsleep\s*\(|benchmark\s*\(|information_schema|;\s*drop\s+table|'\s*--|"
        r"\border\s+by\s+\d+--", re.I),
    "XSS": re.compile(r"<\s*script|on(error|load|mouseover)\s*=|javascript:|<\s*svg|<\s*iframe", re.I),
    "Path traversal": re.compile(r"\.\./|\.\.\\", re.I),
    "Recon / scanning": re.compile(
        r"/\.env$|/\.git/|wp-login\.php|xmlrpc\.php|phpmyadmin|/server-status|"
        r"\.(bak|old|zip|tar\.gz|sql)$", re.I),
    "Web shell": re.compile(r"\.(php|jsp|aspx?)\?.*\b(cmd|exec|command|shell)=", re.I),
}
TOOL_UA = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix", re.I)


def analyze(logfile):
    total = parsed = 0
    ips, statuses = Counter(), Counter()
    hits = defaultdict(Counter)       # rule -> ip -> count
    examples = {}                     # rule -> first decoded example
    tools = Counter()                 # (ip, tool) -> count
    shell_cmds = []

    with open(logfile, errors="ignore") as f:
        for raw in f:
            total += 1
            m = LINE.match(raw)
            if not m:
                continue
            parsed += 1
            ip, status = m["ip"], int(m["status"])
            path = unquote_plus(unquote_plus(m["path"]))   # double-decode catches %252e%252e
            ips[ip] += 1
            statuses[status] += 1

            for name, rx in RULES.items():
                if rx.search(path):
                    hits[name][ip] += 1
                    examples.setdefault(name, (ip, status, path))
            if m["ua"]:
                t = TOOL_UA.search(m["ua"])
                if t:
                    tools[(ip, t.group(0).lower())] += 1
            if RULES["Web shell"].search(path):
                shell_cmds.append((m["time"], ip, status, path.split("=", 1)[1]))

    print(f"[*] {logfile}: {total} lines, {parsed} parsed"
          + (f", {total - parsed} unparsed" if total != parsed else "") + "\n")
    print("=== APACHE ANALYSIS ===")
    print(f"Requests:    {parsed}")
    print(f"Unique IPs:  {len(ips)}")
    print("Status:      " + "  ".join(f"{c}:{n}" for c, n in sorted(statuses.items())))

    print("\nTop talkers:")
    for ip, n in ips.most_common(5):
        flags = [name for name in RULES if ip in hits[name]]
        print(f"  {ip:16s} {n:5d}  {', '.join(flags) if flags else '-'}")

    print("\n[!] Attack patterns (requests / source IPs):")
    for name in RULES:
        n = sum(hits[name].values())
        print(f"  {name:17s} {n:4d} / {len(hits[name])}")

    if tools:
        print("\n[!] Attack tools by User-Agent:")
        for (ip, tool), n in tools.most_common():
            print(f"  {ip:16s} {tool:8s} {n} requests")

    if shell_cmds:
        print(f"\n[!!] WEB SHELL ACTIVITY: {len(shell_cmds)} commands executed")
        for t, ip, status, cmd in shell_cmds[:8]:
            print(f"  {t}  {ip}  {status}  {cmd}")

    print("\nFirst example per rule (decoded):")
    for name, (ip, status, path) in examples.items():
        print(f"  {name:17s} {ip} {status} {path[:70]}")

    return 2 if shell_cmds else (1 if any(hits.values()) else 0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: apache_analyzer.py <access.log>")
        sys.exit(64)
    sys.exit(analyze(sys.argv[1]))
