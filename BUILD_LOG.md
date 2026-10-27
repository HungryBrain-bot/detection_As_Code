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
