# Evidence: B1-T1528-illicit-oauth-consent

Rule version 1, run on 2026-10-27. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B1`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. It runs real KQL, but it is the ADX engine, not Log Analytics; no Sentinel workspace was used.
- The rule targets Sentinel only (Scope, CLAUDE.md); there is no SPL or YARA-L version to run.
- Tables were created from `schemas/reference/sentinel/` with the column types Microsoft publishes in its Azure-Sentinel repository (`Sample Data/Tables/<table>/metadata.json` at c34840b), so dynamic columns are dynamic and `AADNonInteractiveUserSignInLogs` keeps its string-typed `LocationDetails` and `Status`.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 6 | 5 | 5 | 5 | 0 |

Every sample carries `_provenance`: `recorded:<source, file, line @ commit>` or `hand-written` (with a `_note` saying what was changed from which recorded record). A case is one event, or the events that share a `_case` key; the rule must return at least one row per case. New IP addresses in hand-written samples come from documentation ranges (RFC 5737).

## Recorded datasets

Entra ID records in two shapes, rebuilt into Sentinel rows by harness/mapping.py (what that approximates is listed in its docstring):
- Splunk attack_data (Apache 2.0): Azure Monitor diagnostic records from Splunk's attack_range lab tenant. Splunk's dataset notes say tenant ids, user names and IPs were replaced.
- OTRF Security-Datasets (MIT): a Sentinel `AuditLogs` export from the simulated Golden SAML intrusion (SimuLand lab tenant).

| Dataset | Source, file @ commit | Licence | SHA-256 | Records |
|---|---|---|---|---|
| splunk-aad-consent-granted | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_granted/azure_ad_user_consent_granted.log` @ b52ee68 | Apache-2.0 | `c246dccc71905891...` | 10 |
| splunk-aad-consent-declined | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_declined/azure_ad_user_consent_declined.log` @ b52ee68 | Apache-2.0 | `f6f733aae6119421...` | 11 |
| splunk-aad-consent-blocked | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_blocked/azure_ad_user_consent_blocked.log` @ b52ee68 | Apache-2.0 | `2ccc4ae07dd2f0f6...` | 7 |
| otrf-goldensaml-aad-audit | OTRF Security-Datasets, `datasets/compound/GoldenSAMLADFSMailAccess/AADAuditEvents.Zip` @ d9d40ef | MIT | `c45f9b67de7ac1ee...` | 4 |
| splunk-aad-sp-credentials | Splunk attack_data, `datasets/attack_techniques/T1098.001/azure_ad_service_principal_credentials/azure-audit.log` @ b52ee68 | Apache-2.0 | `0a6de8d20356feb0...` | 1 |
| splunk-aad-federated-credential | Splunk attack_data, `datasets/attack_techniques/T1098.001/azure_ad_federated_identity_credential/azure-audit.log` @ b52ee68 | Apache-2.0 | `68a71da7b6ee2370...` | 2 |
| splunk-aad-graph-perm-assigned | Splunk attack_data, `datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log` @ b52ee68 | Apache-2.0 | `5cf32a545e51a98a...` | 52 |

All 87 records were loaded at once. Records of categories with no table here were not loaded: MicrosoftGraphActivityLogs 27, ServicePrincipalSignInLogs 10.

| Engine | Rows returned |
|---|---|
| kusto | 2 |

Both rows are attack activity:
1. 2023-10-27, `user15` consents to "Bad App 1" (365-stealer simulation) for `Mail.Read`, `Mail.ReadWrite`, `Mail.Send` and their `.Shared` forms; the `Consent to application` and `Add delegated permission grant` events share a correlation id and give one row.
2. 2021-08-02, `pgustavo` (SimuLand) grants `Mail.ReadWrite` tenant-wide (`AllPrincipals`) with no consent prompt.

Not matched, as intended: the blocked consent (`Result` failure), the declined consent (no audit grant at all), the `Add service principal` and role-assignment-grant events, and the app credential and manifest changes in the B2 datasets.

## What this does not show

- False-positive rate: the recorded tenants are labs with a handful of audit events, not a production directory where many apps hold mail scopes legitimately.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
- The admin-consent, re-consent and lower-case cases rest on hand-written samples, derived from recorded records with the changes listed in each `_note`.
- Field formats: `ConsentAction.Permissions` is parsed from the text Entra writes; the recorded examples are from 2021 and 2023, and Microsoft does not document this text as a stable format.
