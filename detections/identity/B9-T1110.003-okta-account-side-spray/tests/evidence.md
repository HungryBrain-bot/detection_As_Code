# Evidence: B9-T1110.003-okta-account-side-spray

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B9`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `OktaSSO` created with Microsoft's column names and types (Azure-Sentinel c0c2dc2). Recorded and hand-written samples are raw Okta System Log events, turned into `OktaSSO` rows by `harness/mapping.py` (`from_okta`: nested keys joined with `_`, type suffix added). The Sentinel connector itself was not run, so this is its column naming applied to recorded values, not its output.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 54 | 3 | 3 | 114 | 0 |

All samples are hand-written raw Okta events in the recorded events' shape (`_provenance: hand-written`, a `_note` per event). IPs from RFC 5737; user agent `python-requests/2.34.2` (in Wiz's IOC list, used as an example).

Positive cases: 17 accounts, one wrong password each from 17 IPs (breadth, distributed); 15 accounts from one IP, mixing VERIFICATION_ERROR failures and lockouts (breadth, one IP); 11 accounts failing in one hour and again two hours later (re-targeted).
Negatives (5 scenarios): 25 users mistyping then succeeding; 14 accounts in one hour; a second spray-size hour with 4 accounts overlapping; 20 MFA-factor failures; 20 policy denials with the reason NETWORK_ZONE_BLACKLIST (a hand-written value, not checked against Okta's list). Four loosenings each made at least one negative match (success clause removed: 1 row; 15 to 14: 1; 5 to 4: 1; any `user.*` failure counted: 2).

## Recorded datasets

| Dataset | Source, file @ commit | Licence |
|---|---|---|
| splunk-okta-spray-one-ip | Splunk attack_data, `datasets/attack_techniques/T1110.003/okta_multiple_users_from_ip/okta_multiple_users_from_ip.log` @ b52ee68 | Apache-2.0 |
| splunk-okta-accounts-lockout | Splunk attack_data, `datasets/attack_techniques/T1110/okta_multiple_accounts_lockout/okta_multiple_accounts_lockout.log` @ b52ee68 | Apache-2.0 |

20 recorded events loaded together; 0 rows returned.

0 rows. The recorded spray has 10 accounts (`user.session.start`, INVALID_CREDENTIALS) on 2024-02-28; the lockout set has 7 accounts on 2024-03-01, from the same IP. Neither round reaches 15 accounts. The 10-account round counts as a spray round, but the lockout set is other accounts (user15 to user21) and only 7 of them, so no account fails in two spray rounds and nothing matches. The rule's thresholds were not lowered to fit them. Four debug keys with no `OktaSSO` column were dropped on load (listed in `results/kusto.json`).

## What this does not show

- That the rule catches a real Okta spray: the only recorded one is below its threshold.
- Okta's own definitions of the failure reasons read (the event-type page fetch was incomplete).
- That the Sentinel connector writes these column names in a live workspace (the schema is Microsoft's validation definition).
- Any false-positive rate.
