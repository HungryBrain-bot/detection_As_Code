# Evidence: B14-T1078.004-aws-honeytoken-key-use

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B14`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- Tables: `AWSCloudTrail` with the column types in Microsoft's Azure-Sentinel sample metadata (c0c2dc2); `Honeytoken_CL` as defined by this project (ADR 009, two TokenType values added by ADR 013). Recorded CloudTrail records were mapped to `AWSCloudTrail` columns by `harness/mapping.py` (`from_cloudtrail`); the AWS connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 9 | 4 | 4 | 10 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). IP addresses are from documentation ranges (RFC 5737) or private ranges; the account id, ARNs and key ids are invented and do not have the shape of real secrets.

Registry rows (4) are part of the first positive case and are repeated, without a case, in the negatives.

Positive cases (4): the decoy key calls `GetCallerIdentity` and a denied `ListBuckets`; a decoy secret read by name; a decoy secret read by ARN; a decoy parameter among others in one `GetParameters`.
Negative cases (6): a key id one character from the decoy; a real secret whose name starts with a decoy name, by name and by ARN; a near-name parameter; the decoy name in a CodeBuild `BatchGetProjects` request; an administrator's `ListAccessKeys` on the decoy user with the decoy key id in the request.

Clause loosenings (each made at least one negative match): exact name to `has_any` (2 rows); Secrets Manager / SSM filter removed (1); key also searched in `RequestParameters` (1); key matched on all but its last character (1).

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aws-accessdenied-discovery | Splunk attack_data, `datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json` @ b52ee68 | Apache-2.0 | 1,150 |
| splunk-aws-security-scanner | `datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json` @ b52ee68 | Apache-2.0 | 1,071 |
| splunk-aws-excessive-list | `datasets/attack_techniques/T1580/aws_iam_excessive_list_command_usage/aws_iam_excessive_list_command_usage.json` @ b52ee68 | Apache-2.0 | 4,196 |

| Engine | Rows returned |
|---|---|
| kusto | 0 |

0 rows, as expected: no decoy is in the recorded data. This shows only that the query runs on real CloudTrail records mapped to Sentinel's columns.

## What this does not show

- That a decoy key's first use is always logged: whether every key-validation call (e.g. `sts:GetCallerIdentity`) is in CloudTrail was not confirmed from a fetched AWS page.
- That the connector keeps `requestParameters` as JSON text in `RequestParameters` (the harness mapping assumes so).
- That SSM writes `name` / `names` in `requestParameters` (no recorded SSM event was checked).
- Any false-positive rate; the Log Analytics engine.
