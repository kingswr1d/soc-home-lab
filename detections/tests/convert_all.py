#!/usr/bin/env python3
"""
Convert every Sigma rule to Splunk SPL, Elastic EQL and Microsoft KQL and write
the queries to detections/converted/<target>/<rule>.txt.

Not every backend supports every rule. The combinations that are known not to
work are listed in UNSUPPORTED with the reason; anything else that fails to
convert is an error (exit 1). CI runs this and then checks that the committed
queries in detections/converted/ match the rules (git diff --exit-code).

Usage:
  python detections/tests/convert_all.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "detections" / "converted"
RULE_DIRS = [REPO / "detections" / "rules", REPO / "detection" / "rules"]

TARGETS = {
    "splunk": ["-t", "splunk", "-p", "splunk_windows"],
    "elastic-eql": ["-t", "eql", "-p", "ecs_windows"],
    "kql-defender-xdr": ["-t", "kusto", "-p", "microsoft_xdr"],
}

UNSUPPORTED = {
    # (rule, target): (reason, converter_errors_out)
    ("win_rdp_brute_force.yml", "splunk"):
        ("Splunk backend has no 'temporal_ordered' correlation (failures THEN success)", True),
    ("win_rdp_brute_force.yml", "elastic-eql"):
        ("EQL backend nests the burst sequence inside the chain sequence, which is not valid "
         "EQL; write this one by hand in Elastic", False),
    ("win_rdp_brute_force.yml", "kql-defender-xdr"):
        ("Kusto backend does not support correlation rules", True),
    ("win_brute_force_4625.yml", "kql-defender-xdr"):
        ("Kusto backend does not support correlation rules", True),
    ("win_amsi_bypass.yml", "kql-defender-xdr"):
        ("Defender XDR has no table mapping for PowerShell script block logs (4104)", True),
}


def main() -> int:
    rules = sorted(p for d in RULE_DIRS for p in d.glob("*.yml"))
    errors = 0
    width = max(len(r.name) for r in rules)
    print(f"{'rule':{width}s}  " + "  ".join(f"{t:16s}" for t in TARGETS))
    for rule in rules:
        row = []
        for target, args in TARGETS.items():
            dest = OUT / target / f"{rule.stem}.txt"
            reason, should_error = UNSUPPORTED.get((rule.name, target), (None, False))
            proc = subprocess.run(["sigma", "convert", *args, str(rule)],
                                  capture_output=True, text=True, stdin=subprocess.DEVNULL)
            ok = proc.returncode == 0
            if ok and not reason:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(proc.stdout.strip() + "\n")
                row.append("ok")
            elif reason and ok != should_error:
                # known limitation, behaving as documented
                dest.unlink(missing_ok=True)
                row.append("n/a (documented)")
            elif reason:
                errors += 1
                row.append("CHANGED")
                print(f"  {rule.name} -> {target}: converter behaviour changed "
                      f"({'now errors' if not ok else 'now converts'}); re-check UNSUPPORTED",
                      file=sys.stderr)
            else:
                errors += 1
                row.append("ERROR")
                print(f"  {rule.name} -> {target}:\n{proc.stderr.strip()}", file=sys.stderr)
        print(f"{rule.name:{width}s}  " + "  ".join(f"{c:16s}" for c in row))

    if UNSUPPORTED:
        print("\nn/a reasons:")
        for (rule, target), (reason, _) in UNSUPPORTED.items():
            print(f"  {rule} -> {target}: {reason}")
    print("\nPASS" if not errors else f"\nFAIL: {errors} conversion problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
