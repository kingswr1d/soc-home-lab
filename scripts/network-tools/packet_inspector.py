#!/usr/bin/env python3
"""
PCAP triage with scapy.

Reports:
  - protocol mix (ARP / ICMP / TCP / UDP / DNS)
  - top talkers and top destination ports
  - port scans: one source sending SYNs to many ports on one host
  - DNS: queried domains, flagging long/random-looking names (tunneling, DGA)
  - beaconing: same src->dst:port contacted at a near-fixed interval

Usage:
  python3 packet_inspector.py capture.pcap [--scan-ports 20]
"""
import argparse
import math
import statistics
import sys
from collections import Counter, defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
except ImportError:
    print("scapy is not installed: pip install scapy")
    sys.exit(64)


def entropy(s):
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values()) if s else 0.0


def analyze(path, scan_ports):
    pkts = rdpcap(path)
    protos, talkers, dports = Counter(), Counter(), Counter()
    syn_targets = defaultdict(set)          # (src, dst) -> ports
    flows = defaultdict(list)               # (src, dst, dport) -> [SYN timestamps]
    dns_q = Counter()

    for p in pkts:
        if ARP in p:
            protos["ARP"] += 1
            continue
        if IP not in p:
            protos["other"] += 1
            continue
        src, dst = p[IP].src, p[IP].dst
        talkers[src] += 1
        if DNS in p:
            protos["DNS"] += 1
            if p[DNS].qr == 0 and p.haslayer(DNSQR):
                dns_q[p[DNSQR].qname.decode(errors="ignore").rstrip(".")] += 1
        elif TCP in p:
            protos["TCP"] += 1
            t = p[TCP]
            if t.flags == "S":
                dports[f"tcp/{t.dport}"] += 1   # count new connections, not reply packets
                syn_targets[(src, dst)].add(t.dport)
                flows[(src, dst, t.dport)].append(float(p.time))
        elif UDP in p:
            protos["UDP"] += 1
            if p[UDP].dport < 49152:
                dports[f"udp/{p[UDP].dport}"] += 1
        elif ICMP in p:
            protos["ICMP"] += 1
        else:
            protos["IP-other"] += 1

    dur = float(pkts[-1].time - pkts[0].time) if len(pkts) > 1 else 0
    print(f"[*] {path}: {len(pkts)} packets over {dur / 60:.1f} min\n")
    print("=== PCAP ANALYSIS ===")
    print("Protocols:   " + "  ".join(f"{k}:{v}" for k, v in protos.most_common()))
    print("Top talkers: " + "  ".join(f"{ip}({n})" for ip, n in talkers.most_common(4)))
    print("Top dports:  " + "  ".join(f"{k}({n})" for k, n in dports.most_common(6)))

    scans = [(s, d, ports) for (s, d), ports in syn_targets.items() if len(ports) >= scan_ports]
    print(f"\n[!] Port scans (SYN to >= {scan_ports} ports on one host): {len(scans)}")
    for s, d, ports in sorted(scans, key=lambda x: -len(x[2])):
        sample = ",".join(str(x) for x in sorted(ports)[:8])
        print(f"  {s:15s} -> {d:15s} {len(ports):5d} ports  ({sample},...)")

    odd = [(q, n) for q, n in dns_q.items()
           if len(q.split(".")[0]) > 25 or entropy(q.split(".")[0]) > 3.8]
    print(f"\n[!] DNS: {len(dns_q)} unique names queried, {len(odd)} suspicious "
          f"(long or high-entropy first label)")
    for q, n in sorted(odd, key=lambda x: -x[1])[:5]:
        print(f"  {n:4d}x  {q[:70]}  (entropy {entropy(q.split('.')[0]):.2f})")
    if odd:
        parents = Counter(".".join(q.split(".")[1:]) for q, _ in odd)
        for parent, n in parents.most_common(3):
            print(f"  -> {n} suspicious names under {parent}")

    print("\n[!] Beaconing (>= 6 connections, interval jitter < 10%):")
    found = 0
    for (s, d, port), ts in flows.items():
        if len(ts) < 6:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.mean(gaps)
        if mean > 1 and statistics.pstdev(gaps) / mean < 0.10:
            found += 1
            print(f"  {s:15s} -> {d}:{port}  {len(ts)} connections every ~{mean:.0f}s "
                  f"(jitter {statistics.pstdev(gaps):.1f}s)")
    if not found:
        print("  none")
    return 1 if (scans or odd or found) else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Triage a pcap file")
    ap.add_argument("pcap")
    ap.add_argument("--scan-ports", type=int, default=20)
    a = ap.parse_args()
    sys.exit(analyze(a.pcap, a.scan_ports))
