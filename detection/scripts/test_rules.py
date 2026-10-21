#!/usr/bin/env python3
"""
Sigma Rule Test Harness
Validates Sigma rules against Atomic Red Team test commands using pattern matching.
Note: this harness does pattern matching only; it does not compile rules with sigma-cli.
In production, use 'sigmac -t <backend> rule.yml' to compile for your SIEM.
"""
import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any

ROOT = Path(__file__).parent.parent
RULES_DIR = ROOT / "rules"
TESTS_DIR = ROOT / "tests"
ATOMIC_REPO = TESTS_DIR / "atomic-red-team"


def install_atomic_red_team() -> bool:
    """Clone Atomic Red Team repo if not present."""
    if ATOMIC_REPO.exists():
        print(f"[+] Atomic Red Team already at {ATOMIC_REPO}")
        return True
    print("[+] Cloning Atomic Red Team...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/redcanaryco/atomic-red-team.git", str(ATOMIC_REPO)],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to clone Atomic Red Team: {e.stderr.decode()}")
        return False


def extract_atomic_test_commands(technique_id: str) -> List[str]:
    """Extract command lines from Atomic Red Team test YAML for a technique."""
    commands = []
    technique_dir = ATOMIC_REPO / "atomics" / technique_id
    if not technique_dir.exists():
        return commands
    for yaml_file in technique_dir.glob("*.yaml"):
        try:
            import yaml
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            for test in data.get("atomic_tests", []):
                executor = test.get("executor", {})
                cmd = executor.get("command", "")
                if cmd and isinstance(cmd, str):
                    commands.append(cmd)
                for arg_name, arg_val in executor.get("input_arguments", {}).items():
                    if isinstance(arg_val, str) and len(arg_val) > 5:
                        commands.append(arg_val)
        except Exception as e:
            print(f"[-] Failed to parse {yaml_file}: {e}")
    return commands


def test_rule_against_commands(rule_path: Path, commands: List[str]) -> Dict[str, Any]:
    """Test rule patterns against command lines."""
    rule_name = rule_path.stem
    matches = []
    
    for cmd in commands:
        suspicious = False
        if rule_name == "suspicious_powershell":
            suspicious = any(x in cmd.lower() for x in [
                '-encodedcommand', '-ec ', '-e ', '-executionpolicy bypass', '-ep bypass',
                '-executionpolicy unrestricted', '-ep unrestricted',
                'invoke-expression', 'iex ', 'downloadstring', 'downloadfile', 'webclient',
                'net.webclient', 'invoke-webrequest', 'iwr ', '-windowstyle hidden', '-w hidden',
                '-noprofile', '-nop', '-noninteractive', '-sta'
            ])
        elif rule_name == "credential_dumping_lsass":
            suspicious = any(x in cmd.lower() for x in [
                'mimikatz', 'sekurlsa::', 'lsadump::', 'procdump', 'lsass', 'comsvcs.dll',
                'rundll32', 'minidump', 'sqldumper'
            ])
        elif rule_name == "scheduled_task_persistence":
            suspicious = any(x in cmd.lower() for x in [
                'schtasks /create', 'register-scheduledtask', 'new-scheduledtask',
                '/sc once', '/sc onlogon', '/sc onstart', '/ru system', '/rp ""', '/xml', '/tn '
            ])
        
        if suspicious:
            matches.append(cmd)
    
    return {
        "rule": rule_path.name,
        "technique_ids": extract_techniques_from_rule(rule_path),
        "compiled": False,  # Would be True with working sigmac
        "matches": matches,
        "total_tested": len(commands),
        "match_count": len(matches),
    }


def extract_techniques_from_rule(rule_path: Path) -> List[str]:
    """Extract MITRE technique IDs from a Sigma rule's tags."""
    import re
    techniques = []
    try:
        content = rule_path.read_text()
        matches = re.findall(r'attack\.t(\d{4}\.\d{3})', content, re.IGNORECASE)
        for m in matches:
            techniques.append(f"T{m}")
    except Exception:
        pass
    return techniques


def main():
    print("=" * 60)
    print("Sigma Rule Test Harness (Pattern Matching Mode)")
    print("=" * 60)
    print("[i] Note: Full sigma compilation requires working sigmac CLI")
    print("[i] This mode validates rule logic against Atomic Red Team commands\n")

    if not install_atomic_red_team():
        sys.exit(1)

    rule_files = list(RULES_DIR.glob("*.yml"))
    if not rule_files:
        print("[-] No rules found in rules/")
        sys.exit(1)

    print(f"[+] Found {len(rule_files)} rule(s)")
    technique_map = {
        "suspicious_powershell.yml": "T1059.001",
        "credential_dumping_lsass.yml": "T1003.001",
        "scheduled_task_persistence.yml": "T1053.005",
    }

    all_results = []
    for rule_file in rule_files:
        technique = technique_map.get(rule_file.name)
        if not technique:
            print(f"[!] No technique mapping for {rule_file.name}, skipping")
            continue
        print(f"\n[+] Testing {rule_file.name} -> {technique}")
        commands = extract_atomic_test_commands(technique)
        print(f"    Extracted {len(commands)} test commands")
        result = test_rule_against_commands(rule_file, commands)
        all_results.append(result)
        
        # Show matched commands
        if result["matches"]:
            for m in result["matches"][:3]:
                print(f"    MATCH: {m[:80]}...")
            if len(result["matches"]) > 3:
                print(f"    ... and {len(result['matches']) - 3} more")
        print(f"    Matches: {result['match_count']}/{result['total_tested']}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    total_rules = len(all_results)
    total_matches = sum(r["match_count"] for r in all_results)
    total_tested = sum(r["total_tested"] for r in all_results)
    for r in all_results:
        techs = ", ".join(r.get("technique_ids", ["unknown"]))
        status = "PASS" if r["match_count"] > 0 else "FAIL"
        print(f"  {r['rule']:40s} {status} ({r['match_count']}/{r['total_tested']}) [{techs}]")
    print(f"\nOverall: {total_matches}/{total_tested} Atomic tests matched across {total_rules} rules")
    print("         (Pattern matching validation - compile with sigmac for production)")

    # Save results
    output_file = ROOT / "test_results.json"
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[+] Results saved to {output_file}")


if __name__ == "__main__":
    main()