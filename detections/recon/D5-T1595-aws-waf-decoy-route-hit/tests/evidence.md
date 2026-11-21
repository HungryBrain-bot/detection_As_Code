# Evidence: D5-T1595-aws-waf-decoy-route-hit

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule D5`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- Tables: `AWSWAF` with the column types in Microsoft's Azure-Sentinel sample metadata (c3361d9); `Honeytoken_CL` as defined by this project (ADR 009 / 010). The AWS WAF connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 6 | 3 | 3 | 7 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event), in the shape of Microsoft's ingested sample (request in `HttpRequest`, top-level `ClientIp` / `Uri` empty). Addresses are from documentation ranges (RFC 5737); account ids and resource ids are invented.

Registry rows (2) are part of the first positive case and are repeated, without a case, in the negatives.

Positive cases (3): the decoy route through an ALB, allowed; a second decoy through an API Gateway REST API with the stage as first segment, blocked; the decoy in upper case with a trailing slash through CloudFront.
Negative cases (5): a real route whose name starts with the decoy's; the decoy under two extra segments; the decoy only in the query string; a real route that is a prefix of the decoy; a browser downloading the bundle that carries the decoy.

Clause loosenings (each made at least one negative match): exact match to `has_any` (2 rows); first segment stripped to any prefix up to `/api/` (1); query string searched (1).

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Rows |
|---|---|---|---|
| sentinel-awswaf-ingested-sample | Azure-Sentinel, `Sample Data/ASIM/AWS_WAF_WebSession_AWSWAF_IngestedLogs.csv` @ c3361d9 | MIT | 200 |

| Engine | Rows returned |
|---|---|
| kusto | 0 |

0 rows, as expected: no decoy is in the sample. Microsoft does not say where the sample's requests came from, and its hosts and paths are anonymised; it is background in the connector's shape, not attack data. It is the reason the rule reads `HttpRequest`: every row has the top-level request columns empty.

## What this does not show

- That a real web ACL log reaches Sentinel in this shape (the connector was not run; the sample is Microsoft's).
- Whether WAF's `uri` carries the API Gateway stage.
- That ARTEX or any agent requests a decoy route.
- Any false-positive rate; the Log Analytics engine.
