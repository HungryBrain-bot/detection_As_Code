# Evidence: B7-T1087.004-sp-unlike-its-app

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B7`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `MicrosoftGraphActivityLogs` created from the column types on Microsoft's table reference page (read through a summarising tool).
- `rebase_time: true`: timestamps shifted so the newest event is two minutes before the run, because the query uses `ago()`.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 18 | 2 | 2 | 27 | 0 |

All samples are hand-written. Positive cases: (1) all three signals: `python-requests` lists users and service principals, and a `$expand=owner` query fails with 400 and is corrected to `owners` 28 s later; (2) new client plus listing groups and directory roles.
Negatives: sync app listing with its baseline SDK (enumeration only); new client with single-object reads and a correction after 85 s; delegated calls with a `UserId`; an app with no baseline. Each matched when its clause was removed.

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aad-graph-perm-assigned | Splunk attack_data, `datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log` @ b52ee68 | Apache-2.0 | 52 |

| Engine | Rows returned |
|---|---|
| kusto | 0 |

27 Graph activity records loaded; 16 are app-only, from 5 apps, with user agents `python-requests/2.28.1`, `kiota-dotnet/1.0.0` and empty. They cover about 70 seconds, so after rebasing all fall in the last hour and no app has a 14-day baseline: none is judged. One recorded app reads `auditLogs/signIns` with `python-requests` in normal operation, which is why the rule does not alert on a scripting client alone.

## What this does not show

- That a real agent-driven intrusion is caught; positives are hand-written.
- False-positive rate on a real tenant's 14 days of Graph activity.
- The Log Analytics engine; the column types of `MicrosoftGraphActivityLogs` in a real workspace.
