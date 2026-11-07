# Evidence: E6-T1505.003-webroot-script-file-sysmon

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule E6`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9805.13559, product 2026.11.05.0724-2644-79043d5-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.

## Samples

None. `positive.json` and `negative.json` are empty: the owner asked on 2026-11-07 for the rules and docs first, with samples later. The harness reports 0 positive cases and 0 negatives, which is not a pass on samples.

## Recorded datasets

Splunk attack_data at commit b52ee68 (Apache-2.0): `splunk-sharepoint-webshell-sysmon` (1 event) and `splunk-moveit-webshell-sysmon` (6). 7 events, 7 rows: `w3wp.exe` writing `spinstall0.aspx` under SharePoint `TEMPLATE\LAYOUTS`, and `System` writing `C:\MOVEitTransfer\wwwroot\human2.aspx` six times. Both sets contain only the attack events, so this shows recall on two recorded cases and nothing about false positives.

## What this does not show

- Any false-positive rate, or behaviour on a real server's background activity.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
- Anything about ARTEX: none of the recorded data is ARTEX activity.
