# Evidence: B4-T1078.004-honeytoken-credential-use

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B4`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. It runs real KQL, but it is the ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; there is no SPL or YARA-L version.
- `AADServicePrincipalSignInLogs` and `AzureDiagnostics` were created with the column types in Microsoft's Azure-Sentinel sample metadata (c0c2dc2); `Honeytoken_CL` is defined by this project (ADR 009).

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 5 | 3 | 3 | 7 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). IP addresses are from documentation ranges (RFC 5737), ASNs from the private-use range (RFC 6996) except 8075 (Microsoft).

Positive cases: the decoy app signs in from outside Microsoft's network; a real app reads the decoy secret; the decoy app (id in upper case) is denied a `SecretList` on a real vault.
Negative cases: an ordinary app sign-in; secrets whose names contain or prefix the decoy name; the decoy name in a non-Key-Vault `AzureDiagnostics` record; an app id one character from the decoy. Each was shown to match when the clause guarding it was loosened (exact name match to `has`; Key Vault provider filter removed; decoy app filter widened).

## Recorded datasets

| Dataset | Source, file @ commit | Licence | Records |
|---|---|---|---|
| splunk-aad-graph-perm-assigned | Splunk attack_data, `datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log` @ b52ee68 | Apache-2.0 | 52 |

Loaded: 10 `ServicePrincipalSignInLogs` records (one app, three credential key ids), 27 Graph activity, 13 non-interactive sign-ins, 2 audit records.

| Engine | Rows returned |
|---|---|
| kusto | 0 |

No recorded record involves a honeytoken, and no recorded Key Vault audit log was available, so 0 rows is the expected result and says nothing about catching an attack or about false positives. It shows the query runs on the published schemas.

## What this does not show

- That the rule catches a real attacker using a decoy: all positives are hand-written.
- That Key Vault writes `id_s` and `identity_claim_appid_g` in the form assumed (object URI; app id); taken from Microsoft's logging documentation, not a live vault.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
- Any false-positive rate.
