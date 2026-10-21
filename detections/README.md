# SOC Lab - Sigma Detection Rules

A portfolio-ready collection of Sigma detection rules with test logs and CI validation, designed for a Junior SOC Analyst portfolio.

## Overview

This repository demonstrates practical detection engineering skills by implementing Sigma rules for common ATT&CK techniques, each with:
- **Validated YAML rule** (passes `sigma validate`)
- **Multi-format conversion** (Splunk, Elastic, KQL)
- **Unit test logs** (malicious + benign controls)
- **Automated CI pipeline** (GitHub Actions)

## Rules Inventory

| # | Rule File | MITRE ATT&CK | Technique | Log Source | Severity | Test Log |
|---|-----------|--------------|-----------|------------|----------|----------|
| 1 | `win_brute_force_4625.yml` | T1110.001 / T1110.003 | Password Spraying / Brute Force | Windows Security (4625) | Medium | `win_brute_force_4625.json` |
| 2 | `win_powershell_encoded_command.yml` | T1059.001 / T1027 | PowerShell / Obfuscated Files | Sysmon (1) / 4688 | High | `win_powershell_encoded_command.json` |
| 3 | `win_scheduled_task_creation.yml` | T1053.005 | Scheduled Task Persistence | Sysmon (1) / 4688 | Medium | `win_scheduled_task_creation.json` |
| 4 | `win_lolbin_certutil_download.yml` | T1105 / T1059.001 | Ingress Tool Transfer | Sysmon (1) / 4688 | High | `win_lolbin_certutil_download.json` |
| 5 | `win_powershell_download_cradle.yml` | T1059.001 / T1105 | PowerShell / Ingress Tool Transfer | Sysmon (1) / 4688 | High | `win_powershell_download_cradle.json` |
| 6 | `win_rdp_brute_force.yml` | T1110.001 | RDP Brute Force | Windows Security (4624/4625) | High | `win_rdp_brute_force.json` |
| 7 | `win_amsi_bypass.yml` | T1562.001 | AMSI Bypass / Defense Evasion | PowerShell Script Block (4104) | Critical | `win_amsi_bypass.json` |

## Coverage

- **Tactics**: Credential Access, Execution, Persistence, Defense Evasion, Command & Control
- **Techniques**: 7 ATT&CK (sub)techniques covered
- **Log Sources**: Windows Security (4624/4625), Sysmon/4688 Process Creation, PowerShell Script Block (4104)

## Quick Start

### Local Validation (Linux / macOS)

```bash
# Install sigma-cli
pip install sigma-cli

# Validate all rules
for rule in detections/rules/*.yml; do
  sigma validate --format yaml "$rule"
done

# Convert to Splunk
sigma convert -t splunk detections/rules/win_brute_force_4625.yml

# Convert to Elastic
sigma convert -t elastic detections/rules/win_brute_force_4625.yml

# Convert to KQL (Sentinel/Defender)
sigma convert -t kql detections/rules/win_brute_force_4625.yml
```

### Run Unit Tests (requires sigma-vector)

```bash
pip install sigma-vector

# Test a rule against its malicious test log
sigma-vector --rule detections/rules/win_brute_force_4625.yml \
  --logs detections/test_logs/win_brute_force_4625.json

# Verify no false positives on benign controls
sigma-vector --rule detections/rules/win_brute_force_4625.yml \
  --logs detections/test_logs/benign_controls.json
```

## CI Pipeline

The GitHub Actions workflow (`.github/workflows/sigma-ci.yml`) runs on every push/PR:

1. **Validate** - Syntax check + multi-format conversion (Splunk, Elastic, KQL)
2. **Test** - Execute rules against malicious test logs (should trigger) and benign controls (should not trigger)
3. **Summary** - Overall pass/fail status

## Rule Design Principles

Each rule follows Sigma best practices:
- **Unique ID** (UUID v4)
- **MITRE ATT&CK tags** for mapping
- **Logsource definitions** with requirements
- **Field extraction** for investigation
- **False positive documentation**
- **References** to MITRE and vendor docs
- **Condition logic** using `selection`/`filter`/`condition` blocks
- **Timeframe + count** for threshold-based rules (e.g., brute force)

## Extending the Pack

To add a new rule:

1. Create `detections/rules/win_<technique>.yml` following the template
2. Create `detections/test_logs/win_<technique>.json` with 1+ malicious events
3. Add benign events to `detections/test_logs/benign_controls.json` if needed
4. Push - CI will validate and test automatically

## Portfolio Talking Points

> "I built a CI-tested Sigma rule pack covering 7 ATT&CK techniques across credential access, execution, persistence, defense evasion, and C2. Each rule converts to Splunk, Elastic, and KQL, with unit tests proving detection logic and false positive control. New additions: RDP brute force (T1110.001) with Logon Type 10 correlation, and AMSI bypass (T1562.001) detection via PowerShell Script Block Logging."

## References

- [Sigma Specification](https://github.com/SigmaHQ/sigma/wiki)
- [Sigma CLI](https://github.com/SigmaHQ/sigma/tree/master/tools/sigma-cli)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)