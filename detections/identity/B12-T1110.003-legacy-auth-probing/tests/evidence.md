# Evidence: B12-T1110.003-legacy-auth-probing

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B12`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- Entra sign-in records (recorded and hand-written) are in the Azure Monitor diagnostic format, mapped by `harness/mapping.py`.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 9 | 4 | 4 | 20 | 0 |

All samples are hand-written (`_provenance: hand-written`, a `_note` per event). IPs from RFC 5737.

Positive cases: IMAP4, EWS, AutoDiscover and POP3 failures on 4 accounts from one /24; ROPC failures on 3 accounts; one ROPC attempt answered 50076; one successful Authenticated SMTP sign-in.
Negatives (5 scenarios) and the loosenings that made them match are in the README's Tuning section.

## Recorded datasets

| Dataset | Source, file @ commit | Licence |
|---|---|---|
| splunk-aad-multiple-appids-useragents | Splunk attack_data, `datasets/attack_techniques/T1078/azure_ad_multiple_appids_and_useragents_auth/azure_ad_multiple_appids_and_useragents_auth.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-distributed-spray | Splunk attack_data, `datasets/attack_techniques/T1110.003/azure_ad_distributed_spray/azure_ad_distributed_spray.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-spray-one-ip | Splunk attack_data, `datasets/attack_techniques/T1110.003/password_spraying_azuread/azuread_signin.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-bruteforce-one-user | Splunk attack_data, `datasets/attack_techniques/T1110.001/azure_ad_high_number_of_failed_authentications_for_user/azuread.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-session-cookie-replay | Splunk attack_data, `datasets/attack_techniques/T1185/azure_ad_concurrent_sessions_from_different_ips/azuread.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-success-different-ips | Splunk attack_data, `datasets/attack_techniques/T1110.001/azure_ad_successful_authentication_from_different_ips/azuread.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-granted | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_granted/azure_ad_user_consent_granted.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-declined | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_declined/azure_ad_user_consent_declined.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-consent-blocked | Splunk attack_data, `datasets/attack_techniques/T1528/azure_ad_user_consent_blocked/azure_ad_user_consent_blocked.log` @ b52ee68 | Apache-2.0 |
| splunk-aad-graph-perm-assigned | Splunk attack_data, `datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log` @ b52ee68 | Apache-2.0 |

219 recorded events loaded together; 1 rows returned.

1 row: network 1.2.3.0/24 (Splunk's replacement IP), 2023-10-24 20:00, 4 ROPC attempts on one account answered 50076, apps "Azure Active Directory PowerShell" and "Microsoft Azure PowerShell", from the MFASweep set ("Invoke-MfaSweep with a valid account"). That is a true positive for the password-accepted branch. The two recorded sprays log as "Mobile Apps and Desktop clients" with protocol "none" and return nothing here.

## What this does not show

- Legacy-protocol rows from a recorded tenant: no recorded set has a legacy `ClientAppUsed`; the legacy branch rests on hand-written samples and Microsoft's client names.
- That 50076 always follows a correct password.
- Any false-positive rate, which depends on whether the tenant still allows legacy authentication.
