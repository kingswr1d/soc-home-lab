#!/usr/bin/env python3
"""
SSH brute-force detector for Debian/Ubuntu auth.log (or RHEL /var/log/secure).

What it reports:
  - failed logins per source IP, and which usernames each IP tried
  - invalid (non-existent) usernames tried -> dictionary attack signal
  - brute-force sources: >= --threshold failures from one IP
  - SUCCESS AFTER FAILURES: an "Accepted" login from an IP that already had
    >= --threshold failures earlier in the log. This is the likely-compromise
    alert. A user who mistypes a password once or twice does not trigger it.

Usage:
  python3 ssh_bruteforce_detector.py /var/log/auth.log [--threshold 10]
"""
import argparse
import ipaddress
import re
import sys
from collections import Counter, defaultdict

# "Oct 14 21:37:02 web01 sshd[4242]: ..."  (also sshd-session[...] on OpenSSH 9.8+,
# and ISO timestamps from rsyslog's high-precision format / journalctl -o short-iso)
SYSLOG = re.compile(r'^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) (?P<host>\S+) '
                    r'sshd(?:-session)?\[\d+\]: (?P<msg>.*)$')
FAILED = re.compile(r'Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) '
                    r'from (?P<ip>\S+) port \d+')
ACCEPTED = re.compile(r'Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+')


def clock(ts):
    """Time-of-day part of a syslog ('Oct 14 21:37:02') or ISO timestamp."""
    m = re.search(r"\d{2}:\d{2}:\d{2}", ts)
    return m.group(0) if m else ts


def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def analyze(logfile, threshold):
    fails = Counter()
    streak = Counter()     # failures from an IP since its last successful login
    users_by_ip = defaultdict(Counter)
    invalid_users = Counter()
    first_seen, last_seen = {}, {}
    accepted = []          # (ts, user, ip, method, fails_before)
    lines = sshd_lines = 0

    with open(logfile, errors="ignore") as f:
        for line in f:
            lines += 1
            m = SYSLOG.match(line.rstrip("\n"))
            if not m:
                continue
            sshd_lines += 1
            ts, msg = m["ts"], m["msg"]

            fm = FAILED.search(msg)
            if fm:
                ip, user = fm["ip"], fm["user"]
                fails[ip] += 1
                streak[ip] += 1
                users_by_ip[ip][user] += 1
                if fm["invalid"]:
                    invalid_users[user] += 1
                first_seen.setdefault(ip, ts)
                last_seen[ip] = ts
                continue

            am = ACCEPTED.search(msg)
            if am:
                accepted.append((ts, am["user"], am["ip"], am["method"], streak[am["ip"]]))
                streak[am["ip"]] = 0

    print(f"[*] {logfile}: {lines} lines, {sshd_lines} from sshd\n")
    print("=== SSH ANALYSIS ===")
    print(f"Failed logins:        {sum(fails.values())}")
    print(f"Source IPs w/ fails:  {len(fails)}")
    print(f"Invalid usernames:    {len(invalid_users)} distinct "
          f"({sum(invalid_users.values())} attempts)")
    print(f"Successful logins:    {len(accepted)} "
          f"({sum(1 for a in accepted if a[3] == 'publickey')} publickey, "
          f"{sum(1 for a in accepted if a[3] == 'password')} password)")

    brute = [(ip, n) for ip, n in fails.most_common() if n >= threshold]
    print(f"\n[!] Brute-force sources (>= {threshold} failures): {len(brute)}")
    for ip, n in brute[:10]:
        top = ", ".join(u for u, _ in users_by_ip[ip].most_common(4))
        more = len(users_by_ip[ip]) - 4
        top += f" +{more} more" if more > 0 else ""
        print(f"  {ip:16s} {n:5d} fails  {first_seen[ip]} -> {clock(last_seen[ip])}  users: {top}")

    below = [(ip, n) for ip, n in fails.items() if n < threshold]
    if below:
        print(f"  ({len(below)} more IPs below threshold, {sum(n for _, n in below)} fails total "
              f"-- background scanning)")

    print(f"\n[!] Top invalid usernames tried: "
          + ", ".join(f"{u}({n})" for u, n in invalid_users.most_common(6)))

    hits = [a for a in accepted if a[4] >= threshold]
    print(f"\n[!!] SUCCESS AFTER BRUTE FORCE: {len(hits)}")
    for ts, user, ip, method, before in hits:
        print(f"  {ts}  {user}@{ip}  via {method}  after {before} failed attempts from this IP")
        print(f"       -> likely compromised account. Disable '{user}', kill its sessions, block {ip}.")

    near = [a for a in accepted if 0 < a[4] < threshold]
    for ts, user, ip, method, before in near:
        where = "internal" if is_internal(ip) else "external"
        print(f"  (not flagged: {ts} {user}@{ip} [{where}] logged in after {before} failures "
              f"-- below threshold, likely a typo)")

    return 2 if hits else (1 if brute else 0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Detect SSH brute force in auth.log")
    ap.add_argument("logfile")
    ap.add_argument("--threshold", type=int, default=10,
                    help="failures from one IP before it counts as brute force (default 10)")
    a = ap.parse_args()
    sys.exit(analyze(a.logfile, a.threshold))
