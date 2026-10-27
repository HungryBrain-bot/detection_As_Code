---
name: log-source-gate
description: "Use when a deploy or PR is blocked by the log-source gate, when a team confirms a log source, when adding a customer, log source or team, or when switching a team's reminders to email."
---

# Log-source gate

How the gate decides is in docs/components/log-source-gate.md. This
skill is the operating procedure.

## See what is blocked
```bash
python -m dac gate --customer <id> --siem <sentinel|splunk|secops> --report-only
```
Each `BLOCK` line names the rule, the source and what was found
(no confirmation, or a schema gap from the probe or a customer schema
file). Reminders are in `reports/notifications/<customer>/<siem>-<team>.md`
(and the CI job summary). For schema gaps, use the `schema-check` skill.

A passing live probe confirms a source with no human step, and a
failing probe blocks even over a human confirmation (ADR 005). The
steps below are the human path, used when no probe can run.

## Record a confirmation (the owning team's answer)
Only record a confirmation the owning team actually gave. Never create
one to get a pipeline green: that defeats the gate.

1. Ask the team to check the source in that SIEM (for example,
   "rows in Event with Source Microsoft-Windows-Sysmon and EventID 1 in the last 24h").
2. Commit `customers/<id>/confirmations/<siem>/<log_source>.yaml`:
   ```yaml
   log_source: <id from log_sources.yaml>
   siem: <siem>
   confirmed_by: <team> (<person>)
   confirmed_on: <YYYY-MM-DD>
   evidence: <what they checked, and the result>
   ```
3. Re-run the gate; the rules should move to `ALLOW`.
4. Confirmations expire after 90 days. Renewing is the same file with
   a new date and fresh evidence.

## Add a log source or team
- Source: add it to `log_sources.yaml` with `description`, `owner`
  (a key in `teams.yaml`) and the per-SIEM names the queries use.
  Only list a SIEM where the source is expected to exist.
- Team: add it to the customer's `customers/<id>/teams.yaml` with
  `name` and `email` (may be empty). `python -m dac validate` fails if a
  customer's rules need a team its `teams.yaml` lacks.

## Add a customer
1. `customers/<id>/customer.yaml` with `name`, `siems`, `include`
   (targeted rule ids) and `exclude` (baseline rule ids, with the reason
   in a comment); `customers/<id>/teams.yaml`.
2. In GitHub, create an Environment named `<id>` and add that customer's
   secrets (docs/components/ci.md). Read-only probe access first.

## Switch a team to email
1. Put the address in `customers/<id>/teams.yaml`.
2. Set `SMTP_HOST`, `SMTP_FROM` (and `SMTP_PORT`, `SMTP_USER`,
   `SMTP_PASSWORD` if needed) as secrets in the customer's Environment.
3. No code change. Teams without an address keep getting file and
   job-summary reminders.

## Do NOT
- Don't commit a confirmation on a team's behalf without their answer.
- Don't lower `CONFIRMATION_MAX_AGE_DAYS` or bypass the gate in CI to
  get a deploy through; fix the confirmation instead.
