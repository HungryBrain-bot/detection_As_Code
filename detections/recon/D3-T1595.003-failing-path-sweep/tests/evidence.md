# Evidence: D3-T1595.003-failing-path-sweep

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule D3`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AppServiceHTTPLogs` created with the column types on Microsoft's table reference page (fetched 2026-11-07).

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 95 | 2 | 2 | 385 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). IP addresses are from documentation ranges (RFC 5737); the user agent `python-requests/2.34.2` is the one in Wiz's and Microsoft's indicator lists, used as an example.

Positive cases: 60 distinct paths in two minutes, 90 percent answered 404, 403 or 401; 35 distinct paths, 75 percent answered 404 or 403.
Negative cases (7): 100 requests on 10 paths, all 404; 60 paths with 30 percent errors; 25 paths all failing; 60 paths with 60 percent errors; two clients with 20 failing paths each; 60 paths all 500 or 502; 40 failing paths spread over 24 minutes. Each of five clause loosenings (paths 30 to 20 matched 3; share 0.7 to 0.5 matched 1; distinct to count matched 1; per-client removed matched 1; 5xx counted as errors matched 1) made at least one negative match.

## Recorded datasets

None. No recorded web access log with a path sweep is loaded; `datasets` is empty. Splunk attack_data has web logs for exploits that were not mapped here (see BUILD_LOG.md).

## What this does not show

- That the thresholds (30 paths, 5 minutes, 70 percent) match real sweeps: Wiz gives a rate and a path count for one burst but no error share.
- That real browsing never reaches 30 distinct failing paths in 5 minutes on a real app.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
- Any false-positive rate.
