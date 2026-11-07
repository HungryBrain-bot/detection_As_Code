# Request to a decoy API route

ATT&CK: T1595, T1594 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If a tool reads an app's published OpenAPI spec or JavaScript bundle and
requests the routes it finds, it will request a route that exists only
as bait, which no real client calls. Any request to that route is a
high-confidence signal that someone is working from the published map.
It says nothing about what the requester does next; it fires before any
real exploitation.

## Data sources
- `app-service-http` (app platform team): `AppServiceHTTPLogs`, the
  App Service HTTP access log (needs the diagnostic setting).
- `honeytoken-registry` (detection team): `Honeytoken_CL` rows with
  `TokenType` = `DecoyRoute` and `TokenValue` = the URL path. Same
  contract as B4: the registry job re-sends every active decoy at least
  once per query period (hourly). If it stops, the rule returns nothing
  and cannot say so.
- Apps that are not on App Service (Application Gateway, Front Door, a
  VM) are not covered; their logs have no reference schema here.

## Detection logic
```kql
// D1: decoy route requested (detections/recon/D1-T1595-decoy-route-hit/README.md)
    // The registry must re-send every active decoy route at least once per query period.
    // Route paths are compared as lower case with no trailing slash, on the path only (not the query string).
    let routes = Honeytoken_CL
    | where TokenType == "DecoyRoute"
    | summarize arg_max(TimeGenerated, PlantedIn) by Route = trim_end("/", tolower(TokenValue));
    let decoy_routes = toscalar(routes | summarize make_set(Route));
    // Your own API test tools and authorised scanners, which may call every route in the spec. Fill per customer.
    let known_testers = dynamic([]);
    AppServiceHTTPLogs
    | where not(CIp in (known_testers))
    | extend Route = trim_end("/", tolower(CsUriStem))
    | where Route in (decoy_routes)
    // Any status: a 404 on a route that exists only in the spec is the expected answer, and still a hit.
    | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Requests = count(),
                Methods = make_set(CsMethod, 10), Statuses = make_set(ScStatus, 10),
                UserAgents = make_set(UserAgent, 10), Hosts = make_set(CsHost, 10), Queries = make_set(CsUriQuery, 5)
        by CIp, Route
    | join kind=leftouter routes on Route
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, CIp, Route, PlantedIn, Requests, Methods, Statuses, UserAgents, Hosts, Queries, FirstSeen, LastSeen
```
1. `routes`: active decoy paths from the registry, lower case, no trailing slash.
2. `known_testers`: IPs of your own API test tools and authorised scanners (empty by default).
3. Requests whose path (not query string) equals a decoy path. Any method, any status: the route is usually not implemented, so 404 is the expected answer and still a hit.
4. One row per client IP and route, with methods, statuses, user agents and the query strings seen.

## Why this logic
- The route path is a registry row, not a constant, so adding or retiring a decoy is a data change, not a rule change, and each customer or app can have its own.
- Exact path match, not `contains`: `/api/internal/v1/export-customers-report` or a decoy path inside a `?next=` parameter must not alert (both tested). Case and one trailing slash are normalised because servers and agents differ.
- Alternative, a threshold on 404s: that is D3; this rule needs one request.
- Alternative, alert on the first request to any path not in the spec: needs a complete route inventory, which is what D2's learned baseline approximates and gets wrong for new features.

### How to plant a decoy
1. Pick a path that looks like a real internal route and is unused: same style as your real routes, not a known default (`/admin`, `/debug`).
2. OpenAPI: add it under `paths:` in the spec that is served at the public URL (the file the attacker can fetch), with a plausible summary, one `get` or `post` operation and a `401` response. Do not add it to the internal copy of the spec if the two differ.
   ```yaml
   paths:
     /api/internal/v1/export-customers:
       get:
         summary: Export customer records (internal)
         responses: {"401": {description: Unauthorized}}
   ```
3. JavaScript bundle: the string must survive minification, so a dead `if (false)` branch is removed by the build. Put the path in a data structure the app really uses (a routes table that is read at startup) and check the built output with `grep -r export-customers dist/`. Source maps built from the same source contain it as well; if you stop serving source maps (see the Phase 2 doc's hardening list), the decoy is only in the minified bundle.
4. Do not generate client code from the decoy: SDK generators, Postman collections and spec-driven API tests (for example Schemathesis) call every operation in a spec. Exclude the decoy from generated clients, and put your own test tools' IPs in `known_testers`.
5. The route needs no handler. A 404 is fine; returning 401 for it is also fine. Do not return 200 with data.
6. Add the registry row: `TokenType` `DecoyRoute`, `TokenValue` the path, `PlantedIn` where you planted it. Request the path once from a test address and confirm the alert before relying on it.

## False positives
- Your own API fuzzers, spec-driven test runs, Postman collection runs, link checkers and authorised scanners: they call every route in the spec. Excluded by `known_testers` (empty until filled per customer).
- A partner or customer developer who reads the public spec and tries the route out of curiosity. Rare; the alert is still correct (the route is not for them).
- A decoy path that matches a real route later. Retire the registry row when you add a real route with that path.

## Tuning
- Negatives tested: a path that starts with the decoy path, the parent path, the decoy path in the query string, the decoy path as a suffix of another path, one character short, an ordinary call. Loosening the exact match to `has_any` produced 2 rows from the negative samples; widening to the path plus query string produced 3.
- Production: fill `known_testers`; one decoy per spec is enough to start; alert routing should be higher priority than D2/D3 because the false-positive rate is lowest.

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). 3 of 3 positive cases matched, 0 of 8 negative events. All samples are hand-written. No recorded dataset is loaded: no recorded web access log with a decoy route exists.

## Blind spots
- An agent that never requests the decoy: one that reads only the real routes, or one given a route list that excludes it. No source says how often agents request every route in a spec.
- A decoy only in a source map or spec that the attacker never fetched.
- Requests that the app host does not log (blocked earlier by a WAF or CDN with no access log in this workspace).
- Behind a proxy, `CIp` may be the proxy; the Microsoft page does not say.
- It cannot tell an ARTEX-style agent from a human tester who read the spec.

## References
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- docs/threats/artex-phase2-recon.md (claims checked).
- `schemas/reference/sentinel/AppServiceHTTPLogs.yaml` (Microsoft Learn table reference, fetched 2026-11-07).
