# Rule validation

Code: `dac/validate.py`, `schemas/rule.schema.json`. Run: `python -m dac validate`.

## What it does
Offline checks that every rule folder is complete and internally
consistent before it can be merged.

## How it works
For each `detections/**/rule.yaml`:

| Check | Catches |
|---|---|
| JSON Schema | missing or misspelled fields, bad severity/status, malformed IDs and durations, a rule with no SIEM block |
| Unique IDs | a copied folder that kept its UUID, which would overwrite another rule in the SIEM |
| Log sources | a source not in `log_sources.yaml`, or not declared for a SIEM the rule targets |
| `check_query` per SIEM | truncated queries (bracket/quote balance); a query that never references its declared table / source / log type; Sentinel frequency vs. period; Splunk search with no `index=`; YARA-L header, section order and rule name |
| Docs | `README.md` and `attack.md` present, every required section filled, no TODO, not the template's text left unchanged |
| Tests | `tests/positive.json`, `tests/negative.json`, `tests/evidence.md` present |
| ATT&CK (with `--attack-bundle`) | technique IDs that do not exist, are revoked or deprecated; tactics that are not tactics of the listed techniques |

Schema errors stop the other checks for that rule, since they assume a
well-formed rule.

## Why this method
Each check targets a failure that would otherwise reach the SIEM or a
reviewer unnoticed, and none of them needs a SIEM to run. The ATT&CK
check uses MITRE's own STIX bundle, so a mapping is checked against
current data rather than a list typed by hand.

## What it does not do
- It does not parse KQL, SPL or YARA-L. A query can pass every check
  and still be invalid in its engine. Language-level validation needs
  each vendor's parser or a live instance; Microsoft's open-source
  `Kusto.Language` parser is a candidate for KQL (not added).
- It does not run queries against the sample logs. Whether a rule fires
  on `positive.json` and stays quiet on `negative.json` is checked by
  running it in an engine and recording the result in `evidence.md`.
- It cannot tell whether a doc section is correct, only that it was
  filled in. Accuracy and sourcing are review's job.
- OWASP and ATLAS IDs are format-checked only; OWASP against the 2025
  list. No 2026 list has been confirmed to exist.
