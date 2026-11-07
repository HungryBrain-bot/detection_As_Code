# 012. Foothold rules: IDOR, server processes, web-root files, App Service publishing, request-capture egress (E1-E6, E8, E9)

## Status
Accepted (2026-11-07). Rules `experimental`: no samples yet.

## Context
Phase 4 of the owner's agentic-attack blog series (initial exploitation and
foothold) asks for six detections and a hardening list. Like ADR 009 and
010, this adds rules beyond the original ten (CLAUDE.md, Scope), on the
owner's explicit request in the project thread on 2026-11-07. ADR 011 is
Phase 3 (identity). The owner then asked, the same day, to drop the MySQL
`general_log` rule and to build the rules and docs without test samples
for now.

## Decision
1. Eight Sentinel-only, `targeted` rules in a new track folder
   `detections/foothold/`, IDs E1-E9 with E7 unused (it was the MySQL rule;
   the ID is kept free so the folder names match the draft's order).
2. One rule per data source, not one rule with a union across sources. The
   log-source gate passes a rule only when every source it lists is
   confirmed, so a union rule would be blocked for any customer missing one
   source. The process-chain hypothesis is therefore three rules (E2
   Defender for Endpoint, E3 Windows Sysmon, E4 Sysmon for Linux) and the
   web-root file hypothesis two (E5 Defender, E6 Windows Sysmon).
3. E1 reads `AppServiceHTTPLogs` (ADR 010's verified table), not a new
   gateway or WAF schema. The record ID is taken from the URL by per-app
   patterns; the rule is schema-dependent and says so. Any of three reasons
   (IDs in order, denials mixed with 200s, volume above the host's
   baseline) alerts, with at least 20 distinct IDs in 10 minutes.
4. E8 detects the publishing login in `AppServiceAuditLogs`, not Kudu
   command execution: no Microsoft page read documents a log of Kudu
   commands, and the `Protocol` values for Kudu and Web Deploy are not
   documented, so the rule does not filter on them.
5. E9's domain list is a `let` parameter with only domains confirmed on
   the services' own pages (webhook.site, dnshook.site, six interactsh
   servers). Servers are told from workstations by `DeviceInfo`.
6. Java counts as a server parent in E2-E4 only when its command line names
   an application server; recorded Linux data shows a Maven build starting
   `sh`.
7. All eight rules are `experimental` (deployed disabled) until they have
   positive and negative samples and engine evidence.
8. Harness: `harness/winxml.py` reads Windows event XML lines (Splunk
   attack_data `XmlWinEventLog`) into the OTRF-style events the mapping
   already handles, and Sysmon for Linux lines into `Syslog` rows as
   Microsoft's ASIM parser expects. New Kusto tables: `Syslog`,
   `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`,
   `DeviceInfo`, `AppServiceAuditLogs`. Six Splunk attack_data Sysmon sets
   pinned by commit and SHA-256 (`format: winevent-xml`).
9. New log sources `mde-advanced-hunting`, `windows-file-creation`,
   `linux-sysmon-syslog` (endpoint team) and `app-service-audit` (app
   platform team).

## Consequences
- Evidence is the weakest of any track: no samples at all. Three rules
  (E3, E4, E6) ran on recorded lab data; the other five have never
  matched anything.
- E1-E9 cannot be counted in coverage until they leave `experimental` and
  pass the gate.
- Customers with both Defender and Sysmon get two rules for one
  hypothesis and may see duplicate alerts; include only one of the pair.
- The draft's MySQL and Kudu claims are not supported by any fetched
  source (docs/threats/artex-phase4-foothold.md); E8 is a general App
  Service control, not an ARTEX detection.

## Alternatives considered
- One union rule per hypothesis: blocked by the gate for partial
  customers (point 2).
- An explicit gateway/WAF log schema for E1: no vendor schema was fetched;
  App Service is the one web log verified here.
- `AzureActivity` for App Service publishing-credential reads: operation
  names not verified; parked.
- Defender's own alerts (Microsoft lists several for this campaign):
  better tuned where licensed, not queryable in the harness.
