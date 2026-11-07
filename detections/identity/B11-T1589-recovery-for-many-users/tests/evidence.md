# Evidence: B11-T1589-recovery-for-many-users

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B11`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- Audit records (recorded and hand-written) are in the Azure Monitor diagnostic format, mapped to `AuditLogs` by `harness/mapping.py`.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 10 | 3 | 3 | 25 | 0 |

All samples are hand-written SSPR audit records in the recorded `AuditLogs` shape (`_provenance: hand-written`, a `_note` per event). Activity names follow Microsoft's SSPR reporting page; the initiator `ipAddress`, `ResultReason` step text ("User submitted their user ID") and `category` "UserManagement" are this project's assumptions, not recorded values. IPs from RFC 5737.

Positive cases: SSPR flow started for 4 users from one /24 within 10 minutes; for 3 users from one IP, one of whom completes a reset; 2 users blocked from SSPR within 10 minutes from two networks.
Negatives (7 scenarios) and the loosenings that made them match are in the README's Tuning section.

## Recorded datasets

| Dataset | Source, file @ commit | Licence |
|---|---|---|
| splunk-aad-enable-and-reset | Splunk attack_data, `datasets/attack_techniques/T1098/azure_ad_enable_and_reset/azure-audit.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-granted | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_granted/azure_ad_user_consent_granted.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-declined | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_declined/azure_ad_user_consent_declined.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-blocked | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_blocked/azure_ad_user_consent_blocked.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-sp-credentials | Splunk attack_data, `datasets/attack_techniques/T1098.001/azure_ad_service_principal_credentials/azure-audit.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-federated-credential | Splunk attack_data, `datasets/attack_techniques/T1098.001/azure_ad_federated_identity_credential/azure-audit.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-graph-perm-assigned | Splunk attack_data, `datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log` @ b52ee68 | Apache-2.0 |
| otrf-goldensaml-aad-audit | Splunk attack_data, `datasets/compound/GoldenSAMLADFSMailAccess/AADAuditEvents.Zip` @ d9d40ef | MIT |

93 recorded events loaded together; 0 rows returned.

0 rows. No recorded set has an SSPR activity. The admin reset ("Reset password (by admin)", Splunk `azure_ad_enable_and_reset`) is excluded by design; the other audit sets (consent, credential changes, OTRF Golden SAML) are background.

## What this does not show

- That real SSPR audit records have these values and an initiator IP: all positives are hand-written and no recorded SSPR event exists here.
- That an attacker (ARTEX or other) uses Entra SSPR this way: no fetched source says so.
- Any false-positive rate.
