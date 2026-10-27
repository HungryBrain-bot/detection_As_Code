---
name: new-detection
description: "Use when adding or materially changing a detection rule in detections/ (endpoint, identity or LLM track). Produces the rule, its attack doc, its rule doc, test samples and evidence in one pass, so no rule is merged without its documentation."
---

# New detection

A rule is five artifacts, written together in one PR. A rule without
its docs or evidence is not done, and CI rejects it.

## Before starting
1. Check CLAUDE.md "Scope": the agreed 10 rules. A rule outside that
   list needs the owner's explicit go-ahead first; park it in
   BUILD_LOG.md otherwise.
2. Fetch the primary sources for the attack (vendor report, MITRE
   page, OWASP / ATLAS page). If a source cannot be fetched, it cannot
   be cited. Never cite from memory.

## Steps, in order

### 1. Attack doc first
Copy `templates/attack-doc.md` to
`detections/<track>/<scope #>-<ATTACK-ID>-<short-name>/attack.md`
(e.g. `A1-T1059.001-encoded-powershell`) and fill every
section. "How the attack happens" is from the attacker's side, step
by step, naming real tools. "Real-world use" needs a dated report for
the named group; for the identity and LLM tracks this is what backs
the word "trending". Writing this first is what tells you what the
logs will show.

### 2. Rule
Create `rule.yaml` next to it:
- `id`: a new UUID (`python -c "import uuid; print(uuid.uuid4())"`),
  never reused or changed.
- `status: experimental` until engine evidence exists (deploys
  disabled); `test` once the harness passes (ADR 007).
- `tier`: `baseline` or `targeted`; see the `coverage-map` skill.
- `log_sources`: IDs from `log_sources.yaml`. If a new source is
  needed, add it there with its owning team, and say so in the PR.
- Mapping: ATT&CK technique and tactic, checked against the STIX
  bundle in CI. LLM rules: `owasp_llm_2025` and `atlas`. Follow the
  `coverage-map` skill.
- One block per target SIEM. Sentinel for every rule; `splunk` and
  `secops` only for the four endpoint rules (CLAUDE.md, Scope).
- SecOps rule name must be `dac_<uuid with underscores>`.
- Each SIEM block's `required_fields`: every field the query reads,
  per table / source / log type, in that SIEM's own names. See the
  `schema-check` skill.

### 3. Tests and evidence
- Pick recorded datasets for the technique from `harness/datasets.yaml`,
  or add one (licence that allows reuse, pinned commit and SHA-256).
  List them in `tests/datasets.yaml`.
- `tests/positive.json`: events that must match. `tests/negative.json`:
  similar-looking benign events that must not. Take recorded ones from
  the datasets first (including near-misses in the background), then
  hand-write what the data lacks.
- Label each event `"_provenance": "recorded:<dataset path @ commit>"`
  or `"hand-written"` with a `"_note"`.
- Run `python -m harness run --engine kusto --rule <#> --write` (and
  `--engine splunk` for endpoint rules); see
  docs/components/engine-tests.md. Read every dataset row it returns:
  each must be attack activity, or the rule needs tuning.
- Check the negatives bite: loosen the filter they guard and confirm
  they then match.
- Write `tests/evidence.md` from `tests/results/*.json`: engine and
  version (say "emulator" where it is one), date, datasets, counts,
  and what was not run (YARA-L today). Never imply a run that did not
  happen.

### 4. Rule doc
Copy `templates/rule-doc.md` to `README.md` and fill every section.
"Why this logic" must name at least one alternative and what it would
catch or miss. "Blind spots" must be specific to this rule.

### 5. Check and record
```bash
python -m pytest
python -m harness run --engine kusto
python -m dac validate --attack-bundle data/enterprise-attack.json
python -m dac schema-check --customer demo --siem sentinel
python -m dac gate --customer demo --siem sentinel --report-only
python -m dac plan --siem sentinel
```
Read `build/all/sentinel/<id>.json` as the reviewer will. Then add a dated
entry to BUILD_LOG.md and update CLAUDE.md's rule table.

## Do NOT
- Don't write the docs after the rule is merged.
- Don't present hand-written samples as recorded attack data.
- Don't invent campaign names, dates, report titles or ATT&CK IDs.
- Don't set `status: stable` without a live SIEM run and a production
  false-positive baseline; emulator evidence earns `test`, not `stable`.
