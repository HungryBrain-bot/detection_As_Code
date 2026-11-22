# Evidence: E10-T1190-apigw-sequential-record-access

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule E10`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AWSCloudWatch` created with the columns on Microsoft's table reference page (fetched 2026-11-21); `Message` holds API Gateway access log lines in this project's format.
- `rebase_time: true`: each load's `TimeGenerated` is shifted so the newest row is two minutes old (the query uses `ago()`). The request time inside `Message` is not shifted; the rule bins on it, so only its spacing matters.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 131 | 3 | 3 | 204 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). Addresses are from documentation ranges (RFC 5737); domains, API ids and users are invented. Each case loads the same 60 baseline requests (three days earlier, four ordinary clients, 400 bytes per record), so the volume reason has a baseline (95th percentile 2,000 bytes per client per window).

Positive cases (3), one per reason: 25 customer IDs walked in order, all 200 (`ids-in-order`); 24 random IDs, 10 answered 403 and 14 answered 200 (`denials-mixed-with-200`); 22 random statement IDs at 9,000 bytes each, 99 times the baseline (`volume-above-baseline`).
Negative cases (6): 19 IDs in order; 25 IDs in steps of 10; 25 random IDs all answered 404; 25 random IDs all 200 at ordinary size; 25 IDs in order over 53 minutes; 25 IDs in order split over two users behind one address.

Clause loosenings (each made at least one negative match): distinct IDs 20 to 19 (1 row); step 5 to 10 (1); 200 not required with denials (1); volume ratio 10 to 1 (3); window 10 minutes to 1 hour (1); client = address only (1).

A first run of the negatives placed one case 75 minutes long; the 1-hour `ago()` window then dropped the other cases before any clause was tested, so no loosening bit. The case was shortened to 53 minutes and every loosening was rerun.

## Recorded datasets

None. No public recorded API Gateway access log was found; `datasets` is empty.

## What this does not show

- That real API traffic stays under these thresholds, or that the baseline is stable for a low-traffic API.
- The CloudWatch-to-Sentinel pipeline (not run).
- Any false-positive rate; the Log Analytics engine.
