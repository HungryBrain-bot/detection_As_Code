# Evidence: B10-T1110.003-one-client-many-login-flows

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B10`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- Entra sign-in and audit records (recorded and hand-written) are in the Azure Monitor diagnostic format, mapped by `harness/mapping.py`.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 18 | 4 | 4 | 40 | 0 |

All samples are hand-written (`_provenance: hand-written`, a `_note` per event). The SSPR audit records follow the shape of the recorded `AuditLogs` records, with activity names from Microsoft's SSPR reporting page; the initiator `ipAddress` in them is this project's assumption. IPs from RFC 5737 and RFC 3849 (IPv6).

Positive cases: 4 accounts fail, then IMAP4 from the same /24; 3 accounts locked out (50053), then SSPR for 2 of them; one ROPC attempt, then SSPR for 3 users; 3 accounts fail from one IPv6 /64, then Exchange ActiveSync.
Negatives (7 scenarios) and the loosenings that made them match are in the README's Tuning section.

## Recorded datasets

| Dataset | Source, file @ commit | Licence |
|---|---|---|
| splunk-aad-distributed-spray | Splunk attack_data, `datasets/attack_techniques/T1110.003/azure_ad_distributed_spray/azure_ad_distributed_spray.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-spray-one-ip | Splunk attack_data, `datasets/attack_techniques/T1110.003/password_spraying_azuread/azuread_signin.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-bruteforce-one-user | Splunk attack_data, `datasets/attack_techniques/T1110.001/azure_ad_high_number_of_failed_authentications_for_user/azuread.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-multiple-appids-useragents | Splunk attack_data, `datasets/attack_techniques/T1078/azure_ad_multiple_appids_and_useragents_auth/azure_ad_multiple_appids_and_useragents_auth.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-enable-and-reset | Splunk attack_data, `datasets/attack_techniques/T1098/azure_ad_enable_and_reset/azure-audit.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-session-cookie-replay | Splunk attack_data, `datasets/attack_techniques/T1185/azure_ad_concurrent_sessions_from_different_ips/azuread.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-success-different-ips | Splunk attack_data, `datasets/attack_techniques/T1110.001/azure_ad_successful_authentication_from_different_ips/azuread.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-granted | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_granted/azure_ad_user_consent_granted.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-declined | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_declined/azure_ad_user_consent_declined.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-blocked | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_blocked/azure_ad_user_consent_blocked.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-graph-perm-assigned | Splunk attack_data, `datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log` @ b52ee68 | Apache-2.0 |

225 recorded events loaded together; 0 rows returned.

0 rows. The recorded sprays have one behaviour each (failures; their `ClientAppUsed` is "Mobile Apps and Desktop clients", not legacy); the MFASweep set has ROPC attempts on one account and no failures on others; the admin reset ("Reset password (by admin)") is not an SSPR activity. None of them combines two behaviours from one network.

## What this does not show

- That an agent produces two behaviours from one network within 30 minutes: Wiz reports the behaviours, not their timing per network.
- That SSPR audit records carry the initiator IP.
- Any false-positive rate, in particular behind shared egress.
- The Log Analytics engine.
