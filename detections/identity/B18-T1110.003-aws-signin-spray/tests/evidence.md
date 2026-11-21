# Evidence: B18-T1110.003-aws-signin-spray

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B18`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AWSCloudTrail` with the column types in Microsoft's Azure-Sentinel sample metadata (c0c2dc2). Raw CloudTrail records (recorded and hand-written) were mapped to its columns by `harness/mapping.py` (`from_cloudtrail`; `ResponseElements`, `AdditionalEventData` and `ServiceEventDetails` added for this rule, as JSON text); the AWS connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 80 | 3 | 3 | 158 | 0 |

All samples are hand-written raw CloudTrail records (`_provenance: hand-written`, with a `_note` per event), shaped on AWS's example events and the recorded console sign-ins. Addresses are from documentation ranges (RFC 5737); the account id and user names are invented.

Positive cases (3): an Identity Center spray of 16 users from one address; a mixed spray in one hour, 8 IAM users on the console and 8 Identity Center users, each from its own address; a re-targeted spray, two hours of 12 IAM users each with 6 in both.
Negative cases (6): 25 users fail then succeed in the same hour; 14 accounts fail in an hour; 20 failures for hidden (unknown) user names; two spray hours of 12 accounts with only 4 in both; 6 users failing in three consecutive hours; 16 Identity Center sign-ins that succeed.

Clause loosenings (each made at least one negative match): success clause removed (1 row); 15 to 14 (1); 5 to 4 (1); spray round 10 to 6 (1). Not shown to bite: keeping hidden user names (0 rows; they collapse to one account) and dropping the `PASSWORD` filter (0 rows; no sample has another credential type).

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aws-console-spray | Splunk attack_data, `datasets/attack_techniques/T1110.003/aws_mulitple_failed_console_login/aws_cloudtrail.json` @ b52ee68 | Apache-2.0 | 31 |
| splunk-aws-console-unknown-user | `datasets/attack_techniques/T1110.003/aws_multiple_login_fail_per_user/cloudtrail.json` @ b52ee68 | Apache-2.0 | 28 |
| splunk-aws-console-login-failure | `datasets/attack_techniques/T1110.001/aws_login_failure/aws_cloudtrail_events.json` @ b52ee68 | Apache-2.0 | 7 |
| splunk-aws-root-login-two-ips | `datasets/attack_techniques/T1586.003/aws_console_login_multiple_ips/cloudtrail.json` @ b52ee68 | Apache-2.0 | 8 |

| Engine | Rows returned |
|---|---|
| kusto | 1 |

The row is the recorded spray: reason `breadth`, 31 failing accounts, 31 failures, 1 address, error message "Failed authentication". Nothing from the other three sets: 27 of the 28 failures in the unknown-user set have the user name hidden and are not counted (see README, Blind spots), and the other sets have too few accounts.

## What this does not show

- Any Identity Center event as AWS writes it (no recorded one; the samples follow AWS's documentation example).
- That the AWS connector keeps `responseElements`, `additionalEventData` and `serviceEventDetails` as JSON text in those columns (the harness mapping assumes so).
- Any false-positive rate; the Log Analytics engine.
