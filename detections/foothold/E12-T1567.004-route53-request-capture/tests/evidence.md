# Evidence: E12-T1567.004-route53-request-capture

Rule version 1, run on 2026-11-21. Raw output: `results/kusto.json`.
Rerun: `python -m harness run --engine kusto --rule E12`; see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9820.14516, product 2026.11.20.0756-2646-8369074-master, the Azure Data Explorer emulator. Real KQL, ADX engine, not Log Analytics; no Sentinel workspace was used.
- Sentinel only; no SPL or YARA-L version.
- `AWSRoute53Resolver` created with the columns and types on Microsoft's table reference page (fetched 2026-11-21). The connector itself was not run.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 4 | 3 | 3 | 6 | 0 |

All samples are hand-written (`_provenance: hand-written`, with a `_note` per event). Addresses are private; account, VPC and instance ids are invented.

Positive cases (3): an instance resolves `webhook.site.` and then `WEBHOOK.SITE` (trailing dot and upper case); an interactsh callback name under `oast.fun`; a `TXT` query under `dnshook.site` from a VPC Lambda (no instance id).
Negative cases (6): `notwebhook.site.`, `webhook.site.example.test.`, `oast.pros.`, `docs.webhook-site.example.test.`, an AWS endpoint, `interact.sh.`.

Clause loosenings: matching any name that contains a listed domain (`has`) made `webhook.site.example.test` match (1 row). Dropping the label-boundary check (`endswith Domain` instead of `endswith "." + Domain`) made no negative match: the earlier `has_any` filter already drops `notwebhook.site`, because `has` matches whole terms.

## Recorded datasets

None. No public recorded Route 53 Resolver query log was found; `datasets` is empty.

## What this does not show

- Whether the connector keeps the trailing dot in `QueryName` (both forms tested).
- That `SrcIds` arrives as a dynamic object with an `instance` key in Sentinel.
- Any false-positive rate; the Log Analytics engine.
