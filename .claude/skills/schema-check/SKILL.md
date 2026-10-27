---
name: schema-check
description: "Use when a rule is blocked on a schema gap, when a customer reports their data lands in a different table / index / log type, when writing a rule's required_fields, or when adding a reference schema. Covers Sentinel, Splunk and Google SecOps, each in its own data model."
---

# Schema check

How it works is in docs/components/schema-check.md. This skill is the
procedure.

## Rule of thumb: each SIEM in its own terms
- Sentinel: tables and columns (`SecurityEvent.CommandLine`,
  `Syslog.SyslogMessage`, `CommonSecurityLog.DeviceVendor`).
- Splunk: index + source / sourcetype, and extracted field names
  (add-on or CIM). There is no `Syslog` or `CommonSecurityLog` table in
  Splunk; never carry Sentinel names over.
- SecOps: log type (`WINDOWS_SYSMON`) and UDM paths in snake_case
  (`target.process.command_line`).

## 1. Writing required_fields (with new-detection)
For each SIEM block, list every field the query reads, keyed by the
table / source / log type it reads them from. The key must be one of
the names `log_sources.yaml` declares for the rule's sources.
`python -m dac validate` checks field names against
`schemas/reference/<siem>/` where a reference exists.

## 2. Running it
```bash
python -m dac schema-check --customer <id> --siem <siem>
```
With read-only credentials in the environment it probes the live SIEM;
without them it uses only schema files the customer sent. Output goes
to `reports/schema/<id>/<siem>.md`.

Read-only access per SIEM (never use deploy credentials for probing if
a read-only identity is available):
- Sentinel: Entra app with **Log Analytics Reader** on the workspace,
  plus `SENTINEL_WORKSPACE_ID` (the GUID).
- Splunk: a token whose role can search the relevant indexes.
- SecOps: a viewer role; token minted by workload identity.

## 3. Reading the result
| Status | Meaning | Usual fix |
|---|---|---|
| `missing_table` | Sentinel table not in the workspace | connector not enabled, or data lands elsewhere (step 4) |
| `no_recent_data` | no events in 24h (Splunk/SecOps: or the source does not exist) | ingestion broken, or wrong source name |
| `missing_fields` | table present, fields absent | logging config (e.g. 4688 command-line auditing off), or a different parser (step 4) |
| `not_checked` | no probe credentials and no customer schema | get read-only access, or ask the team for the schema |

## 4. When the customer's data lands elsewhere
Example: all Windows events forwarded into Sentinel's `Syslog`, or
into a Splunk index with a custom sourcetype.

1. Ask the owning team (the gate reminder already does) for the actual
   table / index+sourcetype / log type and its field names.
2. Commit their answer as
   `customers/<id>/schemas/<siem>/<name>.yaml` with `name`, `fields`,
   `provided_by`, `provided_on`, `notes`. Only record what they sent.
3. Decide with the owner how to adapt the rule. The schema check never
   rewrites a rule. Options, in order of preference: the customer fixes
   the integration; a parser or function that maps their table to the
   expected columns; a customer-specific rule variant. Each is a
   reviewed change, with the reason in BUILD_LOG.md.
4. Re-run the schema check and the gate.

## 5. Adding a reference schema
Only from a fetched vendor source. Save to
`schemas/reference/<siem>/<name>.yaml` with `name`, `siem`,
`source_url`, `fetched_on`, `provenance` (how it was fetched, and
anything not yet verified) and `fields`. Never type a field list from
memory.

## Do NOT
- Don't mark a gap as fixed by editing `required_fields` to drop a field
  the query still uses.
- Don't commit a customer schema file the customer did not send.
- Don't describe a probe result as verified against a live API until
  one has run and is logged in BUILD_LOG.md.
