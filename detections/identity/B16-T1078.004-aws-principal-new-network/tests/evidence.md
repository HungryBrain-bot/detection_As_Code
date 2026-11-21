# Evidence: B16-T1078.004-aws-principal-new-network

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B16`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- Tables: as B15. Recorded CloudTrail records were mapped to `AWSCloudTrail` columns by `harness/mapping.py` (`from_cloudtrail`); the AWS connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 126 | 2 | 2 | 98 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). IP addresses are from documentation ranges (RFC 5737) or private ranges; the account id, ARNs and key ids are invented and do not have the shape of real secrets.

Timestamps are rebased (`rebase_time`) so the newest event is two minutes before the run. Lookup rows as in B15.

Positive cases (2): a role with 60 baseline calls over 10 days from the AWS stand-in, then two calls in the last hour from 64512 (two IPs); an IAM user with 60 baseline calls from 64513 and the AWS stand-in, then one call from 64512.
Negative cases (5): a new ASN for a user with only 30 baseline calls; a new IP in a known ASN; a new ASN but the call failed; an address with no lookup row; a private address through a VPC endpoint.

Clause loosenings: minimum baseline removed (1 row); baseline by IP instead of ASN (1); `ErrorCode` filter removed (1); unmatched addresses kept (1). Keeping private addresses made no negative match: the private sample has no lookup row, so the lookup drops it anyway; the filter is redundant here and kept as a guard.

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aws-accessdenied-discovery | Splunk attack_data, `datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json` @ b52ee68 | Apache-2.0 | 1,150 |
| splunk-aws-security-scanner | `datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json` @ b52ee68 | Apache-2.0 | 1,071 |
| splunk-aws-excessive-list | `datasets/attack_techniques/T1580/aws_iam_excessive_list_command_usage/aws_iam_excessive_list_command_usage.json` @ b52ee68 | Apache-2.0 | 4,196 |

| Engine | Rows returned |
|---|---|
| kusto | 0 |

0 rows. Timestamps were rebased (raw CloudTrail `eventTime` is now shifted by the harness; ADR 013). No lookup rows exist for the recorded addresses, so `ipv4_lookup` drops every call.

## What this does not show

- That a real stolen key is caught (hand-written positives).
- That 50 baseline calls is a sensible minimum for a real workload.
- `ipv4_lookup` in Log Analytics; any false-positive rate.
