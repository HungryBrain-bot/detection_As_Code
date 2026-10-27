# 005. Schema check with a read-only probe, used by the gate

## Status
Accepted (2026-10-27). Amends ADR 003.

## Context
ADR 003's gate only knew that a person said a log source was
onboarded; it listed "query the SIEM" as the stronger check it could
not do. Two further problems surfaced in review: a source can be
onboarded but missing the fields a rule reads (command-line auditing
off, so 4688 events have no `CommandLine`), and a customer's data can
land somewhere other than the conventional table (for example every
source forwarded into `Syslog` or `CommonSecurityLog`). Each SIEM
names these things differently: Sentinel has tables, Splunk has
indexes, sources and sourcetypes, SecOps has log types and UDM fields.

## Decision
- **Rules declare what they read.** Each SIEM block has
  `required_fields`: table / source / log type -> fields used by the
  query, in that SIEM's own vocabulary.
- **Reference schemas** from vendor documentation live in
  `schemas/reference/<siem>/`, with source URL, fetch date and
  provenance. The validator checks `required_fields` against them when
  one exists, catching field-name typos before anything is deployed.
- **Each adapter has a read-only probe**: Sentinel runs `getschema` and
  a 24h count through the Log Analytics query API; Splunk runs a 24h
  `fieldsummary` export search; SecOps runs a 24h UDM search and reads
  the field paths in a sample of events.
- **Least privilege.** The probe uses separate, read-only access: for
  Sentinel the same Entra app with the Log Analytics Reader role (deploy
  needs Microsoft Sentinel Contributor instead); for Splunk a token
  whose role can search the relevant indexes; for SecOps a viewer role.
- **The gate uses the result** (amending ADR 003): a passing probe
  auto-confirms a source; a failing probe blocks even when a human
  confirmation exists; with no probe, a human confirmation is required,
  and a schema file the customer sent that lacks required fields blocks.
- **Different integrations are handled by people, not code.** When data
  lands elsewhere, the reminder asks the team for the actual table and
  schema; it is committed to `customers/<id>/schemas/<siem>/` and the
  rule is adapted by hand.

## Alternatives considered
- **Human confirmation only** (ADR 003 as written). Cannot see missing
  fields or stale data, and needs a person for every customer and
  source, which defeats baseline rules (ADR 004).
- **Data presence only (count, no fields).** Catches dead sources, not
  the common "events arrive but the field is empty or absent" case.
- **Automatic rule rewriting to the customer's schema.** Attractive,
  but a wrong field mapping produces a rule that deploys cleanly and
  never fires, which is the failure this check exists to prevent.
  Rewrites stay manual and reviewed.
- **Full parsers (Kusto.Language, SPL, YARA-L) to infer fields from
  queries.** More accurate than a hand-written `required_fields`, but
  three toolchains, and still needs the observed schema to compare to.

## Consequences
- `required_fields` is maintained by hand and can drift from the query.
  Review has to check both together.
- Probe behavior is unverified against every live API. The Sentinel and
  Splunk shapes come from vendor references; the SecOps UDM search
  endpoint and response shape are my reading of the v1alpha API and are
  the least certain.
- Splunk and SecOps cannot tell a missing source from an empty one;
  both report "no events in 24h".
- The SecOps probe reads a sample of 100 events, so a field present on
  only some events can be reported missing.
- Reference schemas exist only for SecurityEvent, Syslog and
  CommonSecurityLog so far. SecurityEvent came through a summarising
  fetch tool; Syslog and CommonSecurityLog come from the Azure-Sentinel
  repo's validation tables, not the Microsoft reference page.
