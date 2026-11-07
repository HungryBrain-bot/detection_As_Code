# Evidence: B5-T1078.004-credential-two-networks

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B5`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AADServicePrincipalSignInLogs` created with the column types in Microsoft's Azure-Sentinel sample metadata (c0c2dc2).

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 4 | 1 | 1 | 6 | 0 |

All samples are hand-written. IPs from RFC 5737 documentation ranges; ASNs 8075 (Microsoft) and private-use ASNs (RFC 6996) standing in for VPS providers.

Positive case: three sign-ins with one key id from AS8075, then one from AS64512.
Negatives: same app with a second key id outside Azure; same key from outside but failed (7000215); same key, no ASN; an app that only signs in from outside Azure. Each was shown to match when its clause was removed (grouping by key id, `ResultType == "0"`, the ASN-not-empty filter, the "both sides" condition).

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aad-graph-perm-assigned | Splunk attack_data, `datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log` @ b52ee68 | Apache-2.0 | 52 |

| Engine | Rows returned |
|---|---|
| kusto | 0 |

The 10 recorded service principal sign-ins (one app, three credential key ids, one IP) have **no `autonomousSystemNumber`** in any record, so the rule filters them all out. The 0 rows show only that the query runs on the published schema.

## What this does not show

- That a real leaked secret is caught: the positive case is hand-written.
- That `AutonomousSystemNumber` is filled for service principal sign-ins in a real tenant (the column exists in Microsoft's schema; the recorded lab records lack it).
- That Azure-hosted apps always sign in from AS8075 [Likely, not checked per service].
- Any false-positive rate; the Log Analytics engine.
