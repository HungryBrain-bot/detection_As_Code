# Evidence: D6-T1595.003-apigw-failing-path-sweep

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule D6`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AWSCloudWatch` created with the columns on Microsoft's table reference page (fetched 2026-11-21); `Message` holds API Gateway access log lines in this project's format (docs/components/apigateway-access-log.md).

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 42 | 1 | 1 | 229 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). Addresses are from documentation ranges (RFC 5737); API ids and domains are invented. `TimeGenerated` is set three minutes after the request time, to stand for ingestion delay; the rule reads the request time.

Positive case: 40 distinct paths in two minutes from one address, 36 answered 404, plus one 401 from the authorizer and a Lambda log line in the same table (skipped).
Negative cases (6): 29 failing paths; 40 paths with half answered 403; 40 failing paths over two addresses; 40 failing paths over 20 minutes; 40 failing paths over two API domains; 40 other JSON log lines that mention `apiId` but have no `status`.

Clause loosenings (each made at least one negative match): paths 30 to 29 (1 row); share 0.7 to 0.5 (1); window 5 to 20 minutes (1); per-address grouping removed (1); per-domain grouping removed (1). Removing the `status` filter made no negative match (see README, Tuning).

## Recorded datasets

None. No public recorded API Gateway access log was found; `datasets` is empty.

## What this does not show

- That API Gateway writes unmatched, throttled or WAF-blocked requests to the access log.
- That the CloudWatch-to-S3 Lambda and the connector deliver `Message` unchanged (read from Microsoft's Lambda code, not run).
- That the thresholds fit real sweeps or real API traffic.
- Any false-positive rate; the Log Analytics engine.
