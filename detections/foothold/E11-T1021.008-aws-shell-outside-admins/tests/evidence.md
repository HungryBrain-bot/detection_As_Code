# Evidence: E11-T1021.008-aws-shell-outside-admins

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule E11`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AWSCloudTrail` with the column types in Microsoft's Azure-Sentinel sample metadata (c0c2dc2). Raw CloudTrail records were mapped by `harness/mapping.py` (`from_cloudtrail`); the AWS connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 3 | 3 | 3 | 6 | 0 |

All samples are hand-written raw CloudTrail records (`_provenance: hand-written`, with a `_note` per event); account ids, ARNs, instance ids and key ids are invented. `admin_identities` is empty, as shipped.

Positive cases (3): an IAM user opens a Session Manager shell; a CI role's serial-console key push, denied; a support role opens a port-forwarding session.
Negative cases (6): `ResumeSession`; `TerminateSession`; `SendCommand` by patch automation; `DescribeInstanceInformation`; `GetSerialConsoleAccessStatus`; `ImportKeyPair`.

Clause loosenings (each made at least one negative match): any SSM, Instance Connect or EC2 call (2 rows); any SSM operation ending in `Session` (1).
Admin list: filled with the three positive identities and the recorded role, the positives plus the recorded set returned 0 rows.

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aws-instance-connect-keys | Splunk attack_data, `datasets/attack_techniques/T1021.008/aws_ec2_multiple_ssh_public_keys_uploaded/aws_ec2_multiple_ssh_public_keys_uploaded.json` @ b52ee68 | Apache-2.0 | 12 |

| Engine | Rows returned |
|---|---|
| kusto | 1 |

The row: identity `arn:aws:iam::111111111111:role/securityresearchrole` (Splunk's sanitised account), 12 `SendSSHPublicKey` calls in 14 seconds to `i-0123456789abcdef0` as `ec2-user`, region eu-west-3. A lab recording of the technique, not ARTEX.

## What this does not show

- A recorded `StartSession` or serial-console event (none found); their samples follow AWS's API reference.
- That the identities in a real account are few enough for an allow list to work.
- Any false-positive rate; the Log Analytics engine.
