# Evidence: B15-T1078.004-aws-key-two-networks

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B15`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- Tables: `AWSCloudTrail` as for D4; `IpAsn_CL` as defined by this project (ADR 013). `ipv4_lookup` ran in the ADX emulator. Recorded CloudTrail records were mapped to `AWSCloudTrail` columns by `harness/mapping.py` (`from_cloudtrail`); the AWS connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 9 | 2 | 2 | 10 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). IP addresses are from documentation ranges (RFC 5737) or private ranges; the account id, ARNs and key ids are invented and do not have the shape of real secrets.

Lookup rows (3) use documentation ranges: 198.51.100.0/24 as AS16509 (standing in for AWS), 203.0.113.0/24 and 192.0.2.0/24 as private-use ASNs 64512 and 64513 (RFC 6996). They are part of the first positive case and repeated in the negatives.

Positive cases (2): an IAM user key making three calls from the AWS stand-in and one from 64512; a role session's temporary key through a VPC endpoint (private address) and then from 64513.
Negative cases (5): same user, a second key outside AWS; app key from outside but failed; app key from an address with no lookup row (198.18.0.9); a key only used outside AWS; that key with one call whose `VpcEndpointId` is `AWS Internal`.

Clause loosenings (each made at least one negative match): `ErrorCode` filter removed; grouped by user instead of key; unknown counted as external; `AWS Internal` treated as a VPC endpoint; both-sides condition removed.

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aws-accessdenied-discovery | Splunk attack_data, `datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json` @ b52ee68 | Apache-2.0 | 1,150 |
| splunk-aws-security-scanner | `datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json` @ b52ee68 | Apache-2.0 | 1,071 |
| splunk-aws-excessive-list | `datasets/attack_techniques/T1580/aws_iam_excessive_list_command_usage/aws_iam_excessive_list_command_usage.json` @ b52ee68 | Apache-2.0 | 4,196 |

| Engine | Rows returned |
|---|---|
| kusto | 0 |

0 rows. No `IpAsn_CL` rows were loaded for the recorded addresses (none were invented), so every recorded call is "unknown" and not counted. This shows only that the query, including `ipv4_lookup`, runs on real records.

## What this does not show

- That a real leaked key is caught: all positives are hand-written.
- That `ipv4_lookup` runs in Log Analytics (its Learn page lists Azure Data Explorer and Fabric only).
- That Amazon's address space is all announced from AS16509 / AS14618 [Guessing].
- Any false-positive rate.
