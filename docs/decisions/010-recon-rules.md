# 010. Recon rules for web apps and AWS (D1-D4)

## Status
Accepted (2026-11-07)

## Context
The owner is writing a blog series on agentic attacks (ARTEX and
similar tools). Phase 1 (credential sourcing) produced B4-B7 (ADR 009).
Phase 2 (recon) describes an agent reading an app's JavaScript, source
maps, runtime config and API documents to map it, then testing routes,
and testing cloud permissions. The owner asked for four detections and
a hardening list. This adds four rules beyond the original ten (CLAUDE.md,
Scope), on the owner's explicit request in the project thread on
2026-11-07.

## Decision
1. Four Sentinel-only, `targeted` rules in a new track folder
   `detections/recon/`: D1 decoy route hit, D2 documents downloaded then
   routes the UI does not call, D3 path sweep with mostly 401/403/404, D4
   authorization-failure burst across AWS services. Hardening items are
   guidance in docs/threats/artex-phase2-recon.md, not rules.
2. Web rules read `AppServiceHTTPLogs` only. It is the one web access log
   whose table reference could be read in full (columns and types). Other
   web logs are parked, not guessed: the Application Gateway field list
   came through a summary and does not say whether `requestUri` carries
   the query string.
3. Decoy route paths are rows in `Honeytoken_CL` with `TokenType`
   `DecoyRoute` (ADR 009's registry, same hourly re-send contract), not
   constants in the query. The route path is therefore a parameter per
   customer and per app, as the owner asked.
4. D2's baseline of UI routes is learned from the app's own traffic: a
   normalised route that at least 3 distinct clients called successfully
   between 14 and 1 days ago. Chosen because it needs no change to the
   app. A build-time route registry is more accurate and is parked.
5. D4 has no Azure branch. The Azure Activity log "doesn't typically
   capture read operations" (Microsoft Learn), and how it records a 403
   was not found in the fetched pages. An `AzureActivity` reference schema
   was written and then removed, since no rule reads it.
6. Thresholds (D2: 3 routes in 10 minutes; D3: 30 distinct paths in 5
   minutes at 70 percent errors; D4: 20 denied calls across 4 services in
   1 minute) are this project's choices. Wiz gives a rate (about one
   request per second, 60+ route variants in two minutes) but no error
   share, and no source gives a permission-check rate for ARTEX.
7. Harness: new tables `AppServiceHTTPLogs` and `AWSCloudTrail`
   (reference schemas under `schemas/reference/sentinel/`); raw CloudTrail
   records, as AWS writes them, are mapped to `AWSCloudTrail` columns by
   `harness/mapping.py`; hand-written rows of both tables load as they are.
   Three recorded Splunk attack_data CloudTrail sets (Apache-2.0, pinned
   by commit and SHA-256) are loaded for D4.
8. New log sources with owners: `app-service-http` (app platform team, a
   new key in the demo customer's teams.yaml) and `aws-cloudtrail` (cloud
   platform team).
9. Each rule has a per-customer allowlist let (`known_testers`,
   `scanner_principals`), empty by default; D3 has none yet.

## Consequences
- Evidence is weaker for D1-D3 than for A1-A4: every positive and
  negative is hand-written, and no recorded web access log with a decoy,
  a documents-then-routes sequence or a path sweep is loaded. D4 is
  better: three recorded CloudTrail sets, though they are scanner tools
  in a lab, not ARTEX.
- The rules are `test` because they pass the harness, not because they
  have seen an agent.
- Running D1-D3 needs the App Service HTTP log diagnostic setting; D4
  needs the AWS S3 connector with management events. The gate's reminders
  to the owning teams are the control.
- D2's baseline gets worse on low-traffic apps and for a day after a
  front-end release; documented in its README.
- Hardening the documents (authentication on Swagger, no source maps)
  turns off D2's first leg by design.

## Alternatives considered
- One combined "recon" rule: harder to tune and to explain; each rule
  tests one hypothesis from the post.
- D1 as constants in the query: a rule change per decoy, and one list for
  all customers.
- D4 on GuardDuty or CloudTrail Insights: better where enabled, but not
  queryable in the harness and not in every customer.
- An Azure Activity branch built from the draft's description: rejected,
  it would rest on an unverified representation of a 403.
