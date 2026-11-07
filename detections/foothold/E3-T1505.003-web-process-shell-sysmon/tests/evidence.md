# Evidence: E3-T1505.003-web-process-shell-sysmon

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule E3`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9805.13559, product 2026.11.05.0724-2644-79043d5-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.

## Samples

None. `positive.json` and `negative.json` are empty: the owner asked on 2026-11-07 for the rules and docs first, with samples later. The harness reports 0 positive cases and 0 negatives, which is not a pass on samples.

## Recorded datasets

Splunk attack_data at commit b52ee68 (Apache-2.0), read by `harness/winxml.py` into `Event` rows: `splunk-wsus-webshell-sysmon` (6 events), `splunk-wsus-sa-webshell-sysmon` (2), `splunk-crushftp-sysmon` (1). 9 events, 1 row: `w3wp.exe` starting `cmd.exe` on the WSUS lab server. Not matched, as designed: `wsusservice.exe`, `WsusService.exe`, `mmc.exe` and `crushftpservice.exe` starting `cmd.exe` (those parents are not in the list), and `cmd.exe` / `powershell.exe` children of `cmd.exe` or `powershell.exe`.

## What this does not show

- Any false-positive rate, or behaviour on a real server's background activity.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
- Anything about ARTEX: none of the recorded data is ARTEX activity.
