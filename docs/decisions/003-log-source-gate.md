# 003. Pre-deploy log-source gate with committed confirmations

## Status
Accepted (2026-10-27)

## Context
A detection deployed against a log source that is not onboarded never
fires, and nothing tells anyone. Most detection-as-code pipelines
validate the rule but not whether its data exists in the target SIEM.
The owner asked for a reminder to the owning team before any rule is
deployed, working without email now and with email later.

## Decision
- Each rule lists log source IDs. `log_sources.yaml` maps each ID to an
  owning team and to the tables / sources / log types per SIEM.
  `teams.yaml` holds each team's name and email.
- A confirmation is a committed file,
  `confirmations/<siem>/<log_source>.yaml`, with `confirmed_by`,
  `confirmed_on` and `evidence`. It covers every rule using that source
  in that SIEM, and expires after 90 days.
- Before deploy, the gate checks each rule's sources. For anything
  missing or expired it sends one reminder per owning team, listing the
  sources and the rules waiting on them, and blocks those rules. Other
  rules still deploy.
- On pull requests the gate runs in report-only mode, so the reminder
  goes out while the rule is still in review. On `main` it blocks.
- Delivery is pluggable: SMTP when `SMTP_HOST`/`SMTP_FROM` are set and
  the team has an email; otherwise a file in `reports/notifications/`
  plus the GitHub job summary. Adding an address is the only change
  needed to switch a team to email.

## Alternatives considered
- **Confirmation per rule.** Every query tweak would need a new
  confirmation from the same team for the same source; teams learn to
  approve without looking.
- **GitHub Environments with required reviewers.** A real approval
  button, but the approval is per deployment, not per log source, and
  it records that someone clicked, not what they checked.
- **Query the SIEM for recent events per source.** The strongest check,
  because it tests the data and not a person's word. It needs live
  credentials, so it cannot run here. It is the natural next step once
  a SIEM is connected: run a "rows in the last 24h" query per source
  inside the gate and require both.

## Consequences
- The gate proves a named person confirmed the source within 90 days.
  It does not prove events are arriving now.
- Reminders are re-sent on every PR run and every push to `main` while
  a source is unconfirmed. Fine for a small repo; would need
  deduplication with many rules and real email.
- A confirmation file is reviewed in a PR like code, so who confirmed
  what, and when, is in git history.
