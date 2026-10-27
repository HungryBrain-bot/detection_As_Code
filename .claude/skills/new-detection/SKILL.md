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
`detections/<track>/<ATTACK-ID>-<short-name>/attack.md` and fill every
section. "How the attack happens" is from the attacker's side, step
by step, naming real tools. "Real-world use" needs a dated report for
the named group; for the identity and LLM tracks this is what backs
the word "trending". Writing this first is what tells you what the
logs will show.

### 2. Rule
Create `rule.yaml` next to it:
- `id`: a new UUID (`python -c "import uuid; print(uuid.uuid4())"`),
  never reused or changed.
- `status: experimental` until evidence exists (deploys disabled).
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
- `tests/positive.json`: events that must match. `tests/negative.json`:
  similar-looking benign events that must not.
- Label each event `"_provenance": "recorded:<dataset/file>"` or
  `"hand-written"`.
- Run the query in an engine and record in `tests/evidence.md`: engine,
  date, dataset and file, positive and negative match counts. If the
  query has not been run, say so there; do not imply it was.

### 4. Rule doc
Copy `templates/rule-doc.md` to `README.md` and fill every section.
"Why this logic" must name at least one alternative and what it would
catch or miss. "Blind spots" must be specific to this rule.

### 5. Check and record
```bash
python -m pytest
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
- Don't set `status: stable` without evidence from a real engine run.
