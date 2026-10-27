# Coverage reporting

Code: `dac/coverage.py`. Decision record: [ADR 006](../decisions/006-coverage-reporting.md).
Run: `python -m dac coverage --customer <id> [--attack-bundle data/enterprise-attack.json]`.

## What it does
Produces, for one customer, the evidence for "which techniques are we
detecting?", in a form a CISO or auditor already reads:

- `reports/coverage/<id>/attack-layer.json`: an ATT&CK Navigator layer
- `reports/coverage/<id>/atlas-layer.json`: the same for MITRE ATLAS
  techniques, when LLM rules apply
- `reports/coverage/<id>/summary.md`: one table, tactic -> technique ->
  rule -> status -> why

## How it works
1. Take the customer's applicable rules: baseline rules not excluded,
   plus targeted rules they include (ADR 004).
2. Run the log-source gate for every SIEM the customer runs, without
   sending reminders. The gate uses the probe when read-only credentials
   exist, otherwise confirmations (ADR 005).
3. A rule is **active** if it passed on at least one of those SIEMs,
   else **blocked**, with the gate's reasons.
4. Per technique: green (score 2) if any of its rules is active, orange
   (score 1) if it only has blocked rules. Each cell's comment lists the
   rules and where they are active.
5. With `--attack-bundle`, the ATT&CK release number from the bundle is
   written into the layer.

In CI this runs on every push to `main`, per customer; the summary is
shown in the job summary and the files are uploaded as an artifact.

## Why this method
The Navigator layer is the format management and auditors already
recognise, so the output needs no new tooling to present. Tying
"active" to the gate means the map shows rules that can run against
confirmed data, not rules that merely exist in the repo. That is the
difference between a coverage claim that survives questions and one
that does not.

## Advantages
- One command per customer; no manual spreadsheet.
- Blocked rules stay visible with the reason, which is itself useful to
  management: it shows which onboarding gaps cost which detections.
- The caveats are written into the summary itself, so they travel with
  it when it is forwarded.

## What it does not do
- "Active" is not "proven to detect". Nothing here measures detection
  quality; that is the per-rule test evidence.
- One rule covers one or two procedures of a technique. A green cell is
  not a fully covered technique.
- Navigator loading is untested; the ATLAS layer's `domain` value is a
  guess (ADR 006).
- No trend over time: each run is a snapshot.
