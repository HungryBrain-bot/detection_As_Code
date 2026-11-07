# Evidence: B13-T1606-oauth-jwt-tampering

Rule version 1, run on 2026-11-07. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule B13`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AppAuthEvent_CL` created from this project's reference schema (ADR 011); hand-written rows load as they are.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 9 | 4 | 4 | 21 | 0 |

All samples are hand-written `AppAuthEvent_CL` rows (`_provenance: hand-written`, a `_note` per event). The request paths and the alg-none shape follow Wiz's log lines; IPs from RFC 5737.

Positive cases: one JWT with `alg` "none" on `/sso`; three `state` mismatches on the Microsoft OAuth callback from one IP; a refused code and a bad-signature JWT from one /24; three unregistered `redirect_uri` variants.
Negatives (5 scenarios) and the loosenings that made them match are in the README's Tuning section.

## Recorded datasets

None. `AppAuthEvent_CL` is defined by this project and no public log of rejected OAuth callbacks or JWTs was found; `datasets` is empty.

## What this does not show

- That any application writes these rows: the table is a design until an app does.
- Thresholds against real traffic.
- That a real attack's rejections group into one /24: Wiz's IOCs suggest it for one actor, not in general.
