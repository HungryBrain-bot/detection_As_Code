# Evidence: D4-T1580-cloud-permission-burst

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule D4`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AWSCloudTrail` created with the column types in Microsoft's Azure-Sentinel sample metadata (c0c2dc2). Recorded CloudTrail records were mapped to its columns by `harness/mapping.py` (`from_cloudtrail`); the AWS connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 54 | 2 | 2 | 193 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). IP addresses are from documentation ranges (RFC 5737); the account id and ARNs are invented.

Positive cases: 24 AccessDenied across 5 services in 50 seconds; 30 `Client.UnauthorizedOperation` across 4 services.
Negative cases (7): 19 denied across 5 services; 30 denied on one service; 30 denied on 3 services; 24 denied split over two bins; two principals with 15 each; 30 `ThrottlingException`; 30 successful calls across 6 services. Each of five clause loosenings made at least one negative match.

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aws-accessdenied-discovery | Splunk attack_data, `datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json` @ b52ee68 | Apache-2.0 | 1,150 |
| splunk-aws-security-scanner | `datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json` @ b52ee68 | Apache-2.0 | 1,071 |
| splunk-aws-excessive-list | `datasets/attack_techniques/T1580/aws_iam_excessive_list_command_usage/aws_iam_excessive_list_command_usage.json` @ b52ee68 | Apache-2.0 | 4,196 |

| Engine | Rows returned |
|---|---|
| kusto | 11 |

All 11 rows are the IAM user `cloudsploit` (one row per minute with at least 20 denied calls across at least 4 services, 73 to 612 denied calls and 4 to 36 services each; the first two files cover the same minutes under different account ids). No row is the `cloudmapper` user (its denied calls are at most 27 in a minute, all on one service) or an ordinary user (`jose_cli`, `test_saml`, `patrick_cli`: no denied calls at all in these files). The tools are posture and mapping scanners in a lab account, run for the dataset; this shows the rule alerts on a real enumeration tool's denial bursts and not on the ordinary users in the same sets, not that it alerts on ARTEX.

## What this does not show

- That ARTEX or any agent produces this pattern: no source fetched says so.
- A false-positive rate: the "ordinary users" are three lab users over a week.
- That the connector writes `ErrorCode` for these records as the harness mapping assumes.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
