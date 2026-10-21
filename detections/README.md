# Sigma detection rules

Sigma rules for common Windows attacks, each with an attack test log, checked against benign controls, and converted to Splunk, Elastic and Microsoft Defender queries. GitHub Actions runs all of it on every push.

## Rules

| Rule file | What it catches | ATT&CK (v20) | Log source | Level |
|---|---|---|---|---|
| `win_brute_force_4625.yml` | 10+ failed logons from one IP in 5 min (correlation rule) | T1110.001, T1110.003 | Security 4625 | medium |
| `win_rdp_brute_force.yml` | 5+ failed RDP logons for one account, **then** a successful RDP logon from the same IP (ordered correlation) | T1110.001, T1078 | Security 4624/4625, Logon Type 10 | high |
| `win_powershell_encoded_command.yml` | `powershell -EncodedCommand <base64>` | T1059.001, T1027 | Sysmon 1 / 4688 | high |
| `win_powershell_download_cradle.yml` | `IEX (New-Object Net.WebClient).DownloadString(...)` and similar | T1059.001, T1105 | Sysmon 1 / 4688 | high |
| `win_lolbin_certutil_download.yml` | `certutil -urlcache -split -f <url>` | T1105 | Sysmon 1 / 4688 | high |
| `win_scheduled_task_creation.yml` | `schtasks /create`, `Register-ScheduledTask`, `at.exe` | T1053.005 | Sysmon 1 / 4688 | medium |
| `win_amsi_bypass.yml` | Writing to AmsiUtils fields, patching AmsiScanBuffer, `'A'+'M'+'S'+'I'` string building. Only *reading* AMSI state is not flagged. | T1685 | PowerShell 4104 | high |

Tactics covered: Credential Access, Initial Access, Execution, Persistence, Privilege Escalation, Stealth, Defense Impairment, Command and Control.

ATT&CK v20 renamed and split some of these: "Defense Evasion" became **Stealth** and **Defense Impairment**, and the old AMSI-bypass technique T1562.001 is now **T1685 Disable or Modify Tools**. The tags here use v20 IDs and the hyphenated tactic names that `sigma check` expects.

The brute-force rules use **Sigma correlation rules** (`correlation: type: event_count` / `temporal_ordered`). The old `| count() > 10` pipe syntax is deprecated, and current Sigma tools reject it.

## Run it locally

```bash
python3 -m venv .venv-sigma && source .venv-sigma/bin/activate
pip install -r detections/requirements.txt

sigma check --fail-on-issues detections/rules/ detection/rules/   # lint: tags, IDs, syntax
python detections/tests/run_tests.py                              # attack logs fire, benign stays clean
python detections/tests/convert_all.py                            # writes detections/converted/
```

`run_tests.py` output:

```
rule file                              alert                                                      attack log   benign
------------------------------------------------------------------------------------------------------------------------
win_amsi_bypass.yml                    PowerShell AMSI Bypass - Tampering With AmsiUtils Fields o fires (4)    clean
win_brute_force_4625.yml               Windows Brute Force / Password Spraying - 10+ Failed Logon fires (1)    clean
win_lolbin_certutil_download.yml       LOLBin Execution - Certutil Download                       fires (1)    clean
win_powershell_download_cradle.yml     PowerShell Web Request / Download Cradle                   fires (1)    clean
win_powershell_encoded_command.yml     PowerShell Encoded Command Execution                       fires (1)    clean
win_rdp_brute_force.yml                RDP Brute Force Followed by Successful Logon               fires (1)    clean
win_scheduled_task_creation.yml        Scheduled Task Creation via schtasks.exe or COM            fires (1)    clean
------------------------------------------------------------------------------------------------------------------------
PASS
```

### How the tests work

`detections/tests/run_tests.py` parses each rule with pySigma (the library `sigma-cli` is built on) and evaluates it against JSON events:

- every alert must fire on its own `test_logs/<rule>.json`
- no alert may fire on `test_logs/benign_controls.json`. That file contains near-misses on purpose: a single failed logon, `schtasks /query`, `certutil -store`, an RDP login after two typos, a script that reads AMSI state.
- correlation rules are evaluated over the events' timestamps, so the RDP rule only fires when the success comes **after** the burst of failures

I checked that the tests can fail. Raising the brute-force threshold to 11 makes it miss its log (10 events). Moving the RDP success before the failures makes the ordered rule miss. The first version of the AMSI rule flagged the benign diagnostic script, and the harness caught it. That's why the rule now requires a field *write*.

## Converted queries

`detections/converted/` holds the generated queries, so you can paste them straight into a SIEM:

| Folder | Backend | Pipeline |
|---|---|---|
| `splunk/` | Splunk SPL | `splunk_windows` |
| `elastic-eql/` | Elastic EQL | `ecs_windows` |
| `kql-defender-xdr/` | Microsoft Defender XDR KQL | `microsoft_xdr` |

CI regenerates them and fails if the committed files are out of date. Some combinations aren't possible with the current backends. Those are listed with the reason in `convert_all.py` and in its output:

- RDP chain → Splunk: no `temporal_ordered` support
- RDP chain → Elastic: the backend produces a nested sequence that isn't valid EQL
- both correlation rules → KQL: the Kusto backend has no correlation support
- AMSI → Defender XDR: Defender has no table for PowerShell script block logs

## Adding a rule

1. `detections/rules/win_<name>.yml`, with a fresh UUID (`python3 -c "import uuid; print(uuid.uuid4())"`)
2. `detections/test_logs/win_<name>.json`, a list of attack events (add `Timestamp` for correlation rules)
3. a near-miss benign event in `test_logs/benign_controls.json`
4. `python detections/tests/convert_all.py`, then commit the rule, logs and `converted/`

## References

- [Sigma specification and correlation rules](https://sigmahq.io/docs/meta/correlations.html)
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) · [pySigma](https://github.com/SigmaHQ/pySigma)
- [MITRE ATT&CK v20](https://attack.mitre.org/)
- [LOLBAS](https://lolbas-project.github.io/)
