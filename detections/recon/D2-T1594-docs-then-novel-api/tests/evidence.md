# Evidence: D2-T1594-docs-then-novel-api

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule D2`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AppServiceHTTPLogs` created with the column types on Microsoft's table reference page (fetched 2026-11-07).

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 207 | 3 | 3 | 611 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event), including the baseline: each case or scenario has its own host with 64 baseline requests (4 routes, 4 clients, days 2 to 5 before the attack). Timestamps are shifted by `rebase_time` so the newest event is two minutes old. IP addresses are from documentation ranges (RFC 5737).

Positive cases: source map and `env.js`, then 4 novel API routes in 4 minutes; `/swagger/`, then 3 novel routes (two ids of one route count once), the last 8 minutes after the download; `/v2/api-docs`, then 3 novel routes.
Negative cases (9): a normal page load with config files and baseline routes (one with a new id); a source map then 2 novel routes; novel routes before the download; novel routes 15 minutes after; the download answered 404; novel routes without a download; download by one client and calls by another; non-API paths after a download; one novel route called three times. Each of eight clause loosenings (routes 3 to 2, window 10 to 60 minutes, document status filter removed, baseline anti-join removed, API prefix removed, same-client join removed, order check removed, distinct count to count) made at least one negative match.

## Recorded datasets

None. `datasets` is empty: no recorded web access log with a UI baseline and a documents-then-routes sequence is in `harness/datasets.yaml`. Splunk attack_data has web server logs of exploits (for example under T1190) but none was mapped here; that is parked in BUILD_LOG.md.

## What this does not show

- That the pattern separates real users from agents on real traffic: all positives and negatives are hand-written, and the baseline is four clients.
- That ARTEX or any agent calls the routes within 10 minutes: Wiz says "minutes"; 10 is this project's choice.
- That the learned baseline works on a low-traffic or newly released app.
- That App Service logs list the requests as assumed, or that the rule runs in Log Analytics.
- Any false-positive rate.
