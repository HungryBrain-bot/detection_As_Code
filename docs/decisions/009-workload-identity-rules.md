# 009. Workload-identity rules for leaked app secrets (B4-B7)

## Status
Accepted (2026-11-07)

## Context
The owner is writing a blog series on agentic attacks (ARTEX and
similar tools) and asked for detection rules wherever the Phase 1 post
(credential sourcing) suggests one. Microsoft's 2026-11-05 report
describes agents finding client secrets on GitHub and reaching Key
Vault in five minutes. The existing identity rules (B1-B3) read user
sign-ins and audit logs only; nothing here read service principal
sign-ins, Graph activity or Key Vault. This adds four rules beyond the
original ten (CLAUDE.md, Scope), on the owner's explicit request in the
project thread on 2026-11-07.

## Decision
1. Four Sentinel-only, `targeted` rules: B4 honeytoken use, B5 one
   credential from Microsoft's network and outside it, B6 a service
   principal from an ASN new in 14 days, B7 app-only Graph calls with
   two of new client / enumeration / fix-and-retry. The self-search for
   leaked secrets is a hunt (docs/hunts/H1), not a rule: the attacker's
   search is not in the customer's logs.
2. New tables, with reference schemas: `AADServicePrincipalSignInLogs`
   and `AzureDiagnostics` from Microsoft's Azure-Sentinel sample
   metadata (read with git); `MicrosoftGraphActivityLogs` from
   Microsoft's table reference page (summarising fetch, labelled).
3. Honeytokens live in `Honeytoken_CL`, a table this project defines,
   re-sent at least hourly; the same contract as `LLMCanary_CL` (ADR
   008). A Sentinel watchlist is the better operational home, but the
   emulator has no `_GetWatchlist`.
4. Network kind is approximated by ASN. Microsoft's network is AS8075
   (Microsoft Learn); B5's `internal_asns` is a per-customer setting.
5. The harness maps the Azure Monitor categories
   `ServicePrincipalSignInLogs` and `MicrosoftGraphActivityLogs` to
   tables (previously counted and skipped), loads hand-written rows of
   the new tables in table shape, and `rebase_time` now also shifts the
   `time` of recorded Azure Monitor records.
6. New log sources with owners: `entra-sp-signin`,
   `entra-graph-activity` (identity team), `azure-keyvault-audit`
   (cloud platform team), `honeytoken-registry` (detection team).

## Consequences
- Evidence is weaker than for B1-B2: every positive is hand-written.
  The only recorded data (Splunk attack_data, one lab tenant) has 10
  service principal sign-ins with no ASN and 27 Graph calls covering 70
  seconds, so B5-B7 cannot match it and B4 has no decoy in it. The rules
  are `test` because they pass the harness, not because they have seen
  an attack.
- B5 and B6 are blind to attacker infrastructure inside Azure.
- Two of the four depend on columns (ASN on service principal
  sign-ins) whose population in a real tenant was not checked.
- Running B4-B7 needs diagnostic settings that are off by default
  (service principal sign-ins, Graph activity, Key Vault). The gate's
  reminders to the owning teams are the control for that.
- The existing B1-B3 result files (2026-10-27) still say these two
  categories were not loaded; their match counts are unchanged
  (full Kusto run on 2026-11-07).

## Alternatives considered
- Entra ID Protection workload identity risk detections: better where
  licensed; not every customer has it, and they are not queryable in the
  emulator.
- Only the Sentinel HoneyTokens solution: covers Key Vault decoys, not a
  decoy app credential planted in a repo.
- One combined "agent behaviour" rule: harder to tune and to explain;
  each rule here tests one hypothesis from the post.
