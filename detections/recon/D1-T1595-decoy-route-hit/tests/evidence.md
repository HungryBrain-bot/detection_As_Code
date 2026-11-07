# Evidence: D1-T1595-decoy-route-hit

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule D1`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AppServiceHTTPLogs` created with the column types on Microsoft's table reference page (fetched 2026-11-07); `Honeytoken_CL` is defined by this project (ADR 009, extended by ADR 010).

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 6 | 3 | 3 | 8 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). IP addresses are from documentation ranges (RFC 5737); the hosts and paths are invented.

Positive cases: the planted route requested with GET (404); the same route in other case, with a trailing slash, POST (401); a second registered route (200).
Negative cases: a path that starts with the decoy path; its parent; the decoy path only in the query string; the decoy path as a suffix of another path; one character short; an ordinary call. Each was shown to match when the clause guarding it was loosened (exact match to `has_any`: 2 rows; path plus query string: 3 rows).

## Recorded datasets

None. No recorded web access log with a decoy route exists, and none of the recorded sets in `harness/datasets.yaml` is a web access log, so `datasets` is empty and 0 rows from 0 events is the recorded result.

## What this does not show

- That an ARTEX-style agent requests a decoy route. No source tested this.
- That App Service writes `CsUriStem` as the path alone for every request type (taken from the table reference, not a live app).
- That the rule runs in a Log Analytics workspace (ADX engine instead).
- Any false-positive rate.
