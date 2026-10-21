#!/usr/bin/env python3
"""
Build a small synthetic pcap for practising with packet_inspector.py.

Contains: normal HTTPS + DNS browsing, an nmap-style SYN scan, a C2 beacon
every 60s (small jitter), and DNS tunneling (long base32 subdomains).
External IPs are RFC 5737 documentation addresses. Requires scapy.

Usage:
  python3 generate_sample_pcap.py [--out logs/sample.pcap] [--seed N]
"""
import argparse
import base64
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap

REPO_ROOT = Path(__file__).resolve().parents[2]
T0 = 1792015200.0  # 2026-10-14 08:00 SAST
GW = "10.0.0.1"
# Fixed MACs so scapy doesn't try (and fail) to ARP-resolve addresses while building frames.
ETH = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
SITES = {"www.google.com": "192.0.2.10", "github.com": "192.0.2.20",
         "outlook.office365.com": "192.0.2.30", "www.news24.com": "192.0.2.40",
         "fnb.co.za": "192.0.2.50"}


def build(rng):
    pkts = []

    def add(t, pkt):
        pkt.time = t
        pkts.append(pkt)

    hosts = [f"10.0.0.{i}" for i in (21, 22, 34, 40, 57)]
    # normal browsing: DNS lookup, then a TLS session
    for _ in range(140):
        t = T0 + rng.uniform(0, 1800)
        h, (name, ip) = rng.choice(hosts), rng.choice(list(SITES.items()))
        sport, qid = rng.randint(49152, 65535), rng.randint(0, 65535)
        add(t, ETH / IP(src=h, dst=GW) / UDP(sport=sport, dport=53) /
            DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
        add(t + 0.02, ETH / IP(src=GW, dst=h) / UDP(sport=53, dport=sport) /
            DNS(id=qid, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=ip)))
        cport, t = rng.randint(49152, 65535), t + 0.05
        add(t, ETH / IP(src=h, dst=ip) / TCP(sport=cport, dport=443, flags="S"))
        add(t + 0.03, ETH / IP(src=ip, dst=h) / TCP(sport=443, dport=cport, flags="SA"))
        add(t + 0.031, ETH / IP(src=h, dst=ip) / TCP(sport=cport, dport=443, flags="A"))
        for k in range(rng.randint(4, 14)):
            src, dst, sp, dp = (h, ip, cport, 443) if k % 3 == 0 else (ip, h, 443, cport)
            add(t + 0.05 + k * 0.01, ETH / IP(src=src, dst=dst) /
                TCP(sport=sp, dport=dp, flags="PA") / bytes(rng.randint(60, 1400)))

    # SYN scan from an internal box against the file server
    t, scanner, target = T0 + 600, "10.0.0.66", "10.0.0.10"
    open_ports = {22, 80, 139, 445}
    ports = list(range(1, 1025))
    rng.shuffle(ports)
    for port in ports:
        sp = rng.randint(40000, 65000)
        add(t, ETH / IP(src=scanner, dst=target) / TCP(sport=sp, dport=port, flags="S"))
        flags = "SA" if port in open_ports else "RA"
        add(t + 0.0004, ETH / IP(src=target, dst=scanner) / TCP(sport=port, dport=sp, flags=flags))
        t += rng.uniform(0.001, 0.004)

    # C2 beacon: 10.0.0.34 -> 203.0.113.200:8443 every ~60s
    t = T0 + 37
    while t < T0 + 1800:
        sp = rng.randint(49152, 65535)
        add(t, ETH / IP(src="10.0.0.34", dst="203.0.113.200") / TCP(sport=sp, dport=8443, flags="S"))
        add(t + 0.18, ETH / IP(src="203.0.113.200", dst="10.0.0.34") / TCP(sport=8443, dport=sp, flags="SA"))
        add(t + 0.2, ETH / IP(src="10.0.0.34", dst="203.0.113.200") /
            TCP(sport=sp, dport=8443, flags="PA") / bytes(rng.randint(180, 260)))
        t += 60 + rng.uniform(-2, 2)

    # DNS tunneling: data chunks base32-encoded into subdomains
    secret = bytes(rng.getrandbits(8) for _ in range(900))
    t = T0 + 1200
    for i in range(0, len(secret), 30):
        label = base64.b32encode(secret[i:i + 30]).decode().rstrip("=").lower()
        name = f"{label}.x.cdn-update.example"
        add(t, ETH / IP(src="10.0.0.57", dst=GW) / UDP(sport=rng.randint(49152, 65535), dport=53) /
            DNS(id=rng.randint(0, 65535), rd=1, qd=DNSQR(qname=name, qtype="TXT")))
        t += rng.uniform(0.5, 2.0)

    pkts.sort(key=lambda p: p.time)
    return pkts


def main():
    ap = argparse.ArgumentParser(description="Generate a synthetic practice pcap.")
    ap.add_argument("--out", default=str(REPO_ROOT / "logs" / "sample.pcap"))
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args()
    pkts = build(random.Random(a.seed))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(a.out, pkts)
    print(f"[+] {a.out}: {len(pkts)} packets")


if __name__ == "__main__":
    main()
