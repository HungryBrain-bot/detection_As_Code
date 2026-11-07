# One client reads many record IDs in sequence or with many denials

ATT&CK: T1190 · Severity: Medium · Status: experimental · Tier: targeted · Targets: sentinel

## Hypothesis
If a client is working through an insecure direct object reference (IDOR),
changing a record ID and checking each answer, then within minutes one
client asks one host for dozens of distinct record IDs, and at least one of
these shows: the IDs mostly go up in small steps, a large share of answers
are 403 or 404 with some 200s among them, or the client receives far more
bytes than clients of that host normally do. A real customer opens their
own few records.

## Data sources
- `app-service-http` (app platform team): `AppServiceHTTPLogs` (columns and
  types from Microsoft's table reference, fetched 2026-11-07).
- Prerequisite: the App Service HTTP log diagnostic setting is on. Apps
  behind other front ends (Application Gateway, Front Door, a VM web
  server, an API gateway) are not covered; their logs have no reference
  schema here (ADR 010, 012).
- Schema-dependent: the rule only works where the record ID is in the URL.
  `record_path` and `record_query` are per-app patterns; an app that puts
  the ID in a POST body or a header produces nothing.
- Client is `CIp` plus `CsUsername` when the app logs one. There is no
  session column in this table; a session cookie is in `Cookie` but its
  name differs per app, so it is not used.

## Detection logic
```kql
// see rule.yaml for the full query
```
1. Extract a record ID from the path (a numeric segment after a record noun
   such as `/loans/`, `/customers/`, `/accounts/`) or from an `...id=`
   query parameter. Rows without one are dropped.
2. Baseline: per host, the 95th percentile of bytes one client received in
   one 10-minute bin, from 14 days to 1 day ago.
3. Last hour, per host, client and 10-minute bin: distinct IDs, the share
   of consecutive requests whose ID went up by 1 to 5, the share answered
   403 or 404, the count answered 200, and bytes received.
4. Alert on at least 20 distinct IDs and at least one reason:
   `ids-in-order` (60 percent of steps in order), `denials-mixed-with-200`
   (30 percent 403/404 and at least one 200), `volume-above-baseline`
   (10 times the host's 95th percentile). The reasons are in the alert.

## Why this logic
- Distinct IDs, not request count: a user refreshing one record is not a
  walk.
- Three reasons, any one: the owner's draft lists the three signals
  separately. Requiring all three would miss an agent that walks
  non-sequential IDs (GUIDs it scraped, IDs from a list) or one that gets
  200 for every ID because the bug lets it read them all.
- 403/404 must be mixed with 200: a run of only 404s is a sweep of
  missing records, which D3 covers; the IDOR case is that some answers
  succeed.
- Volume against the host's own baseline, not a fixed byte count: record
  sizes differ by app by orders of magnitude.
- 10-minute fixed bins: a walk split by a bin edge can fall under 20 in
  each bin (blind spot below). A sliding window would fix that at the
  cost of a heavier query.
- Thresholds (20 IDs, 10 minutes, 60 percent, 30 percent, 10 times) are
  this project's choices. No fetched source gives a rate, an ID count or
  an error share for IDOR exploitation by an agent.
- Zscaler (2026-10-14) recommends this kind of check ("alert on
  sequential lookups and unusually high numbers of records accessed per
  session"), and Recorded Future (2026-10-16) recommends watching for
  "repeated requests for different customers' records". Neither reports
  a measured pattern.

## False positives
- Back-office staff working a queue of records: usually random order and
  normal sizes, so no reason fires; a queue sorted by ID will fire
  `ids-in-order`. Exclude by user or IP per customer.
- Exports, reports and sync jobs that page through records by ID. Exclude
  by client IP or user agent.
- Search-engine and monitoring crawlers on public record pages.
- Mobile apps that prefetch lists of records.

## Tuning
- Fill `record_path` / `record_query` for each app; the defaults are a
  starting list of nouns and `*id=` parameters.
- No negative scenarios have been run yet; thresholds are untested on
  real or hand-written traffic.
- Before alerting, run the query over two weeks of real traffic and count
  how many clients each reason would have flagged.

## Test evidence
Not run. No positive or negative samples exist yet and the query has not
been executed in the Kusto emulator. The rule is `experimental`, so it is
deployed disabled. See [tests/evidence.md](tests/evidence.md).

## Blind spots
- Record IDs that are not in the URL, or not numeric (GUIDs are dropped by
  the default patterns; `ids-in-order` cannot apply to them anyway).
- A slow walk (under 20 IDs in any 10-minute bin) or one spread over many
  source IPs.
- A walk split across a bin edge.
- Apps that answer 200 with an empty or error body for records the
  caller may not see.
- Clients behind a proxy where `CIp` is the proxy.

## References
- Zscaler ThreatLabz, "Threat Actor Abuses Agentic AI Pentesting Framework to Target South Korean Financial Institutions", 2026-10-14, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (fetched 2026-11-07)
- Recorded Future, "TAG-217 Targets South Korean Financial Services with ARTEX", 2026-10-16, https://www.recordedfuture.com/blog/tag-217-artex-south-korean-banks (fetched 2026-11-07)
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- MITRE ATT&CK T1190 (enterprise bundle, mitre/cti master, fetched 2026-11-07)
- docs/threats/artex-phase4-foothold.md; ADR 012
