# Evidence: B2-T1098.001-app-credential-or-permission

Rule version 1, run on 2026-10-27. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B2`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. It runs real KQL, but it is the ADX engine, not Log Analytics; no Sentinel workspace was used.
- The rule targets Sentinel only (Scope, CLAUDE.md); there is no SPL or YARA-L version to run.
- Tables were created from `schemas/reference/sentinel/` with the column types Microsoft publishes in its Azure-Sentinel repository (`Sample Data/Tables/<table>/metadata.json` at c34840b), so dynamic columns are dynamic and `AADNonInteractiveUserSignInLogs` keeps its string-typed `LocationDetails` and `Status`.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 5 | 5 | 5 | 6 | 0 |

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
| kusto | 4 |

All four rows are the recorded attack or test activity:
1-2. 2021-08-02, `pgustavo` (SimuLand) adds secret `SimuLandCreds` to `SimuLandApp`. The OTRF export contains this audit row twice (same `Id`); both copies are loaded, as recorded, so it gives two rows.
3. 2023-07-24, `tommyr` adds secret `test-creds` to `test-app` (Splunk: "Manually added new client credentials").
4. 2026-06-10, a federated identity credential trusting `repo:external-contractor/infra-automation` on GitHub Actions is added to service principal `prod-deployment-sp`.

Not matched, as intended: the service principal rename in the federated-credential dataset, both `Update application` manifest changes that add a Graph permission to `RequiredResourceAccess` (a requested permission, not a granted one), and the consent datasets' events.

## What this does not show

- False-positive rate: in production most credential additions are developers and pipelines rotating secrets.
- The `Add app role assignment to service principal` branch rests on hand-written samples only: no recorded dataset available here contains that event. Its property names (`AppRole.Value`, `ServicePrincipal.DisplayName`) come from Microsoft's Sentinel rule `AzureADRoleManagementPermissionGrant.yaml`, not from a recorded event.
- `Add service principal credentials` (credentials on the service principal rather than the application) is also hand-written only.
- The federated-credential dataset is dated 2026-06-10 and Splunk replaced its tenant details; it is used as published.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
