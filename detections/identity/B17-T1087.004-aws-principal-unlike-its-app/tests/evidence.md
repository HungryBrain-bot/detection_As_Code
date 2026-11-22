# Evidence: B17-T1087.004-aws-principal-unlike-its-app

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B17`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- Tables: `AWSCloudTrail` as for D4. Recorded CloudTrail records were mapped to `AWSCloudTrail` columns by `harness/mapping.py` (`from_cloudtrail`); the AWS connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 94 | 2 | 2 | 309 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). IP addresses are from documentation ranges (RFC 5737) or private ranges; the account id, ARNs and key ids are invented and do not have the shape of real secrets.

Timestamps are rebased (`rebase_time`).

Positive cases (2): a role with 40 baseline workload calls (Boto3, S3 and SQS) that in the last hour uses the AWS CLI for six discovery calls it never made (new client + enumeration); an IAM user with the same kind of baseline that makes the six discovery calls with its usual SDK, has `GetObject` denied on a guessed bucket name and succeeds 28 seconds later with the corrected name (enumeration + fix-and-retry).
Negative cases (8): new client only; new discovery calls only; new client and 4 new discovery calls; new client and a throttled call followed by a different call; new client and a retry after 90 s; new client and the same request succeeding again; a user with no baseline; calls made by CloudFormation for the user.

Clause loosenings: one signal enough (6 rows); threshold 4 (1); throttling kept (1); window 120 s (1); same parameters allowed (1); `invokedBy` calls kept (1); baseline not required (1).

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aws-accessdenied-discovery | Splunk attack_data, `datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json` @ b52ee68 | Apache-2.0 | 1,150 |
| splunk-aws-security-scanner | `datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json` @ b52ee68 | Apache-2.0 | 1,071 |
| splunk-aws-excessive-list | `datasets/attack_techniques/T1580/aws_iam_excessive_list_command_usage/aws_iam_excessive_list_command_usage.json` @ b52ee68 | Apache-2.0 | 4,196 |

| Engine | Rows returned |
|---|---|
| kusto | 0 |

0 rows, with timestamps rebased so the last recorded hour (ordinary users `jose_cli`, `test_saml`, `patrick_cli`) is "now". The scanner users (`cloudsploit`, `cloudmapper`) are not in that hour and have no earlier history in these files, so B17 could not judge them anyway (D4 alerts on `cloudsploit`). Two things the recorded data changed in the rule: some user agents are logged as `[aws-cli/...]` (brackets now stripped), and raw CloudTrail timestamps were not being rebased (harness fixed).

## What this does not show

- That an agent driving an AWS key behaves this way: no fetched source shows it on AWS.
- Any false-positive rate: the ordinary users are three lab users over a week.
- The Log Analytics engine.
