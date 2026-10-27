# Rule validation

Code: `dac/validate.py`, `schemas/rule.schema.json`, `schemas/reference/`. Run: `python -m dac validate`.

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
| `check_query` per SIEM | truncated queries (bracket and string-literal balance, using each language's literals: KQL `@"..."` / `@'...'`, SPL `"..."`, YARA-L `` `...` ``); a query that never references its declared table / source / log type; Sentinel frequency vs. period; Splunk search with no `index=`; YARA-L header, section order and rule name |
| Docs | `README.md` and `attack.md` present, every required section filled, no TODO, not the template's text left unchanged |
| Tests | `tests/positive.json`, `tests/negative.json`, `tests/evidence.md` present |
| `required_fields` | a field list naming a table / source / log type the rule's log sources do not declare; with a reference schema in `schemas/reference/<siem>/`, field names that do not exist (typos) |
| Customers | unknown SIEMs, `include`/`exclude` naming rules that do not exist, an owning team the customer's rules need missing from its `teams.yaml` |
| ATT&CK (with `--attack-bundle`) | technique IDs that do not exist, are revoked or deprecated; tactics that are not tactics of the listed techniques |
| ATLAS (with `--atlas-data`, atlas-data `dist/v6` YAML) | ATLAS technique IDs that do not exist or are deprecated |
| LLM telemetry | a rule reading `LLMAppLog_CL` without `llm_telemetry.populated`, or naming columns there it does not read (ADR 008) |
| LLM inventory | `llm_log_inventory.yaml` entries missing keys, with unknown kinds or statuses, unknown log sources, columns outside the normalised schema, or no integration entry per SIEM; `llm_apps.yaml` naming unknown sources, columns or teams (docs/components/llm-telemetry.md) |

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
  the engine harness (docs/components/engine-tests.md), which runs the
  KQL in the Kusto emulator and the SPL in a local Splunk; its result
  goes into `evidence.md`.
- It cannot tell whether a doc section is correct, only that it was
  filled in. Accuracy and sourcing are review's job.
- Field names are only checked where a reference schema exists
  (Sentinel SecurityEvent, Event, Syslog, CommonSecurityLog so far).
  Fields inside `Event.EventData` (Sysmon) are not columns and are not
  checked.
- OWASP and ATLAS IDs are format-checked only; OWASP against the 2025
  list. No 2026 list has been confirmed to exist.
