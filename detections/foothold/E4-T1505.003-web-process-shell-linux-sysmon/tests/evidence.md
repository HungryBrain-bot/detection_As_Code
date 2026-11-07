# Evidence: E4-T1505.003-web-process-shell-linux-sysmon

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule E4`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9805.13559, product 2026.11.05.0724-2644-79043d5-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.

## Samples

None. `positive.json` and `negative.json` are empty: the owner asked on 2026-11-07 for the rules and docs first, with samples later. The harness reports 0 positive cases and 0 negatives, which is not a pass on samples.

## Recorded datasets

Splunk attack_data at commit b52ee68 (Apache-2.0), `splunk-java-shell-linux-sysmon`: 42 Sysmon for Linux process events, loaded as `Syslog` rows with the XML in `SyslogMessage` by `harness/winxml.py`. 0 rows. The set's java events are a Maven build starting `/bin/sh`; the rule's app-server marker check excludes them, which is the intended result. The set has no web server starting a shell, so it shows only that this one false-positive shape stays quiet.

## What this does not show

- Any false-positive rate, or behaviour on a real server's background activity.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
- Anything about ARTEX: none of the recorded data is ARTEX activity.
