# Evidence: B3-T1550.001-session-token-replay

Rule version 1, run on 2026-10-27. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B3`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. It runs real KQL, but it is the ADX engine, not Log Analytics; no Sentinel workspace was used.
- The rule targets Sentinel only (Scope, CLAUDE.md); there is no SPL or YARA-L version to run.
- Tables were created from `schemas/reference/sentinel/` with the column types Microsoft publishes in its Azure-Sentinel repository (`Sample Data/Tables/<table>/metadata.json` at c34840b), so dynamic columns are dynamic and `AADNonInteractiveUserSignInLogs` keeps its string-typed `LocationDetails` and `Status`.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 4 | 2 | 2 | 6 | 0 |

Every sample carries `_provenance`: `recorded:<source, file, line @ commit>` or `hand-written` (with a `_note` saying what was changed from which recorded record). A case is one event, or the events that share a `_case` key; the rule must return at least one row per case. New IP addresses in hand-written samples come from documentation ranges (RFC 5737).

## Recorded datasets

Entra ID records in two shapes, rebuilt into Sentinel rows by harness/mapping.py (what that approximates is listed in its docstring):
- Splunk attack_data (Apache 2.0): Azure Monitor diagnostic records from Splunk's attack_range lab tenant. Splunk's dataset notes say tenant ids, user names and IPs were replaced.
- OTRF Security-Datasets (MIT): a Sentinel `AuditLogs` export from the simulated Golden SAML intrusion (SimuLand lab tenant).

| Dataset | Source, file @ commit | Licence | SHA-256 | Records |
|---|---|---|---|---|
| splunk-aad-session-cookie-replay | Splunk attack_data, `datasets/attack_techniques/T1185/azure_ad_concurrent_sessions_from_different_ips/azuread.log` @ b52ee68 | Apache-2.0 | `e8dcbe04a2ee019a...` | 22 |
| splunk-aad-success-different-ips | Splunk attack_data, `datasets/attack_techniques/T1110.001/azure_ad_successful_authentication_from_different_ips/azuread.log` @ b52ee68 | Apache-2.0 | `7de7bf2e60ee2746...` | 15 |
| splunk-aad-multiple-appids-useragents | Splunk attack_data, `datasets/attack_techniques/T1078/azure_ad_multiple_appids_and_useragents_auth/azure_ad_multiple_appids_and_useragents_auth.log` @ b52ee68 | Apache-2.0 | `58b05aa2bfa6af25...` | 10 |
| splunk-aad-consent-granted | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_granted/azure_ad_user_consent_granted.log` @ b52ee68 | Apache-2.0 | `c246dccc71905891...` | 10 |
| splunk-aad-consent-declined | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_declined/azure_ad_user_consent_declined.log` @ b52ee68 | Apache-2.0 | `f6f733aae6119421...` | 11 |
| splunk-aad-consent-blocked | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_blocked/azure_ad_user_consent_blocked.log` @ b52ee68 | Apache-2.0 | `2ccc4ae07dd2f0f6...` | 7 |
| splunk-aad-graph-perm-assigned | Splunk attack_data, `datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log` @ b52ee68 | Apache-2.0 | `5cf32a545e51a98a...` | 52 |

All 127 records were loaded at once. Records of categories with no table here were not loaded: MicrosoftGraphActivityLogs 27, ServicePrincipalSignInLogs 10.

| Engine | Rows returned |
|---|---|
| kusto | 0 |

**No recorded record can exercise this rule.** None of the 81 user sign-in records among them (SignInLogs and NonInteractiveUserSignInLogs) has a `sessionId` (the property is absent from every record, including the Evilginx2 session-cookie replay), so the rule's key is empty and every record is filtered out. The 0 rows say nothing about false positives or about catching the recorded attack.

Even with a session id, the recorded replay would not match: both IP addresses in it are in the same country and the same ASN (16509), and the rule needs two countries. That is the rule's main blind spot, shown by real data.

## What this does not show

- That the rule catches a real replay: both positive cases are hand-written. They are copies of recorded records (the Evilginx2 replay and an interactive sign-in) with a session id added and, for the replayed record, a new IP and country.
- False-positive rate: no recorded data with session ids was available. Expect hits from VPNs and from users whose session follows them across a border.
- That `SessionId` is filled in a real tenant's `SigninLogs` and `AADNonInteractiveUserSignInLogs` for these sign-ins; the column exists in Microsoft's published schema, and Microsoft's session cookie theft playbook investigates by session id, but no live tenant was checked.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
