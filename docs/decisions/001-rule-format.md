# 001. One YAML file per rule, with a native query block per SIEM

## Status
Accepted (2026-10-27)

## Context
Rules must deploy to Microsoft Sentinel (KQL), Splunk (SPL) and Google
SecOps (YARA-L). Each rule also needs metadata the pipeline acts on:
a stable ID, ATT&CK / OWASP mapping, severity, status, and the log
sources it depends on (for the log-source gate, ADR 003).

## Decision
Each rule is `detections/<track>/<folder>/rule.yaml` with shared
metadata at the top and an optional `sentinel:`, `splunk:` and
`secops:` block, each holding that SIEM's native query. A rule targets
exactly the SIEMs it has blocks for. The format is enforced by
`schemas/rule.schema.json`.

## Alternatives considered
- **Sigma as the single source, converted per SIEM.** One logic to
  maintain is the main appeal. Rejected for now: the Splunk backend is
  mature, but conversion to KQL and especially to YARA-L is less
  certain (I am not aware of a maintained YARA-L backend [unverified]),
  and the identity and LLM rules use tables (AuditLogs, a custom LLM
  log) that Sigma's taxonomy does not model well. Converted queries are
  also harder to explain line by line in an interview than ones written
  for the engine. Sigma can still be added later as an extra block.
- **The Azure-Sentinel repo's analytics-rule YAML.** Deployable as is,
  but Sentinel-only; adding SPL and YARA-L would mean bolting fields
  onto someone else's schema.
- **One file per SIEM per rule.** Lets each file match its vendor's
  format exactly, but splits one detection's metadata across three
  files that can drift apart.

## Consequences
- A detection's logic is written once per SIEM, by hand. The 10-rule
  scope keeps this manageable: Sentinel for all 10, Splunk and SecOps
  for the 4 endpoint rules (decision recorded in BUILD_LOG.md,
  2026-10-27).
- Logic drift between the three queries of one rule is possible and is
  not detected automatically. The rule doc's "Detection logic" section
  must explain each version and where they differ.
- The rule ID is a UUID that never changes, so renaming a rule never
  creates a duplicate in a SIEM.
