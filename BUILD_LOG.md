# Build Log

## 2026-10-27 - Plan and scope

- Plan agreed with the owner in the project thread: 10 rules in three
  tracks (4 endpoint, 3 identity/OAuth, 3 LLM app), about 3 weeks,
  every rule with an attack doc and a rule doc written as it is built.
- SIEM coverage decided: Sentinel (KQL) for all 10 rules; Splunk (SPL)
  and Google SecOps (YARA-L) for the 4 endpoint rules only. Reason: the
  identity and LLM rules use Entra and custom tables that would need
  invented field mappings on Splunk and SecOps.
- Noted for the record: Google SecOps uses YARA-L, not YARA.

## 2026-10-27 - Pipeline (no rules yet)

- Built the rule schema, `dac validate`, the `SiemAdapter` interface
  with Sentinel, Splunk and SecOps adapters, the log-source gate with
  file and SMTP notifiers, the CLI, and the GitHub Actions workflow.
  Decisions in ADRs 001-003.
- Gate design change while building: confirmations are per log source
  per SIEM (not per rule), with 90-day expiry, so one confirmation
  covers every rule on that source (ADR 003).
- Added a check that a doc section is not the template's text left
  unchanged, since "filled in" by copying the template would otherwise
  pass.
- Real vs. mocked: no live SIEM or SMTP. Adapter tests run against a
  fake transport with response bodies written from vendor docs
  (`tests/fixtures/api/README.md`). Dry-run is the only deploy that has
  happened.
- Verified: 59 tests pass; yamllint clean; `dac validate` against the
  live MITRE enterprise ATT&CK bundle passes on the fixture rule, and
  the planned rules' technique IDs (T1059.001, T1547.001, T1003.002,
  T1105, T1528, T1098.001, T1550.001) all exist and are not deprecated.
- The repo was empty, so `main` was started with a one-file initial
  commit to give the first PR a base.
- Next: day-1 checks (free Azure Data Explorer cluster, OTRF /
  EVTX-ATTACK-SAMPLES coverage for A1-A4, ATLAS IDs for C1-C3), then
  rule A1 end to end.

## 2026-10-27 - Customers, baseline tier, schema check, coverage

- Owner reviewed PR #1 (merged, CI green) and asked for: a schema-aware
  log-source check using the SIEM itself (e.g. the Sentinel app
  registration querying tables), SIEM-specific (tables vs. indexes vs.
  log types); per-customer ATT&CK / ATLAS coverage for management; and
  high-value rules on native tables pushed to every customer.
- Decided: per-customer folders with one fictional `demo` customer
  (owner chose this on the decision card); `tier: baseline | targeted`;
  baseline still passes the gate, but a passing read-only probe
  auto-confirms a source, so baseline needs no human step where probe
  credentials exist. ADRs 004-006, ADR 003 amended.
- Built: `required_fields` per SIEM block; reference schemas for
  Sentinel SecurityEvent, Syslog, CommonSecurityLog; read-only probes in
  all three adapters; `dac/schema_check.py`; gate rewritten per
  customer with probe auto-confirm and veto and SIEM-specific "your data
  may land elsewhere, send the schema" reminders; `dac/coverage.py`
  (ATT&CK layer, ATLAS layer, summary); CLI commands `customers`,
  `schema-check`, `coverage`; CI matrix per customer x SIEM with one
  GitHub Environment per customer; skills `schema-check` and
  `coverage-map`; component docs for both.
- Real vs. mocked / unverified:
  - No live probe or deploy has run. Probe tests use response bodies
    written from vendor docs. The SecOps UDM search endpoint and
    response shape are a guess at the v1alpha API.
  - SecurityEvent's field list came through a summarising web fetch
    (learn.microsoft.com is blocked from the build environment by
    direct download); not yet checked character by character.
    Syslog and CommonSecurityLog are verbatim from the Azure-Sentinel
    repo's KQL-validation table definitions, not the Microsoft page.
  - No Splunk or SecOps reference schemas yet.
  - Navigator layer loading untested; ATLAS layer `domain` is a guess.
- Parked for the owner (not in scope, not built): common baseline rules
  outside the agreed 10, such as brute-force sign-ins and privileged AD
  group changes. Adding any of them is a scope change.
- Tests: 96 passed; yamllint and pyflakes clean.
- Next: unchanged. Day-1 checks, then rule A1. The pipeline is frozen
  until A1-A4 exist.
