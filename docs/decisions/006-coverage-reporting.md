# 006. Per-customer coverage as Navigator layers plus a summary

## Status
Accepted (2026-10-27)

## Context
The owner wants detection coverage per customer that can be shown to
senior management or a CISO: which ATT&CK techniques (and ATLAS
techniques for the LLM rules) each customer is protected against.
Coverage maps are easy to overstate: a coloured cell reads as "covered"
whether or not the rule can actually run.

## Decision
- `python -m dac coverage --customer <id>` writes, per customer:
  an ATT&CK Navigator layer, an ATLAS layer if any LLM rule applies, and
  a Markdown summary table.
- **Only gate-passed rules count.** A rule is *active* if it passed the
  log-source gate (probe or confirmation) on at least one SIEM the
  customer runs. Applicable but blocked rules are shown in a different
  colour with the reason, and are not counted.
- The summary states, in the document itself, that "active" means
  deployable with confirmed data, not proven detection, and that one
  rule covers one or two procedures of a technique, not all of them.
- Coverage is regenerated on every push to `main` and published as a CI
  artifact and job summary; the files are not committed.

## Alternatives considered
- **Count every rule in the repo.** Inflates coverage with rules the
  customer cannot run.
- **A dashboard.** More presentable, but another system to host; the
  Navigator is the format CISOs and auditors already recognise, and the
  summary converts to any slide.
- **Per-procedure scoring** (weighting by how many procedures a rule
  covers). More honest, but needs procedure-level data per technique
  that this project does not have.

## Consequences
- Coverage is only as good as the gate's evidence: with no probe
  credentials, it rests on human confirmations.
- Navigator layer format 4.5 / Navigator 5.1.0 fields are written from
  the format spec; loading in a live Navigator has not been tested. The
  ATLAS layer uses `"domain": "atlas"`, which is a guess at what the
  ATLAS Navigator expects and is unverified.
