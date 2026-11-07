# Evidence: E5-T1505.003-webroot-script-file-mde

Rule version 1. **Not run.** No engine has executed this rule.

## Engines

- Sentinel query: not run in the Kusto emulator or in any Log Analytics workspace.
- Sentinel only; no SPL or YARA-L version.

## Samples

None. `positive.json` and `negative.json` are empty: the owner asked on 2026-11-07 for the rules and docs first, with samples later. The harness skips this rule (no `tests/datasets.yaml`).

## Recorded datasets

None run. See the README's Test evidence section for recorded data pinned in `harness/datasets.yaml` that this rule could be run against.

## What this does not show

Anything about whether the query runs, matches what it should, or stays quiet on ordinary activity. The rule is `experimental` and is deployed disabled.
