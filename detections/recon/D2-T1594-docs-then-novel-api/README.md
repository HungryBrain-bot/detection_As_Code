# Client downloads API docs or source maps, then calls API routes the UI does not

ATT&CK: T1594, T1595 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If an agent builds its list of routes from a published source map,
config file or API document, then within minutes the same client will
call several API routes that the app's own front-end does not call. A
real user loads the page and calls the routes the UI needs, in that
order. The order (documents first, then routes the UI never uses) is
the signal, not either half.

## Data sources
- `app-service-http` (app platform team): `AppServiceHTTPLogs`, 14 days retained (the query period; the first 13 days are the baseline).
- Same coverage limits as D1: App Service only.

## Detection logic
```kql
// D2: docs or maps downloaded, then routes the UI does not call (detections/recon/D2-T1594-docs-then-novel-api/README.md)
    let recent = 1h;                // alert on activity in this window; the rest of the period is baseline
    let baseline_end = 1d;          // baseline = [14d, 1d) ago, so a client's own requests today do not teach the baseline
    let min_baseline_clients = 3;   // a route is "the UI's" if at least this many distinct clients called it successfully
    let follow_window = 10m;        // calls count if they come within this long after the first document download
    let min_novel_routes = 3;       // distinct novel routes needed
    // Per app: the path prefix of its API. Change for apps whose API is not under /api/.
    let api_prefix = @"^/api/";
    // Published maps and configs (Wiz saw .js.map, /assets/config.json, /env.js, /swagger/?format=openapi).
    let doc_pattern = @"(?i)(\.(js|css)\.map$|/swagger(\.json|/index\.html|/v[0-9]+/swagger\.json)?/?$|/openapi\.(json|yaml)$|/v[23]/api-docs$|/(runtime-)?config\.json$|/env\.js$|/runtime-config(\.js|\.json)?$)";
    // Numeric and GUID path segments become {fcb38bdd-ec7c-4d4c-9c52-30cf6c148699}, twice so that /1/2 is handled.
    let norm = (p: string) {
        let a = tolower(p);
        let b = replace_regex(a, @"/([0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)", @"/{fcb38bdd-ec7c-4d4c-9c52-30cf6c148699}\2");
        replace_regex(b, @"/([0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)", @"/{fcb38bdd-ec7c-4d4c-9c52-30cf6c148699}\2")
    };
    let ui_routes = AppServiceHTTPLogs
    | where TimeGenerated < ago(baseline_end) and ScStatus < 400 and CsUriStem matches regex api_prefix
    | extend Route = norm(CsUriStem)
    | summarize Clients = dcount(CIp) by CsHost, Route
    | where Clients >= min_baseline_clients
    | project CsHost, Route;
    let docs = AppServiceHTTPLogs
    | where TimeGenerated >= ago(recent) and ScStatus < 400 and CsUriStem matches regex doc_pattern
    | summarize DocTime = min(TimeGenerated), DocFiles = make_set(CsUriStem, 10) by CIp, CsHost;
    let calls = AppServiceHTTPLogs
    | where TimeGenerated >= ago(recent) and CsUriStem matches regex api_prefix
    | extend Route = norm(CsUriStem)
    | join kind=leftanti ui_routes on CsHost, Route
    | project CIp, CsHost, CallTime = TimeGenerated, Route, CsMethod, ScStatus, UserAgent;
    docs
    | join kind=inner calls on CIp, CsHost
    | where CallTime between (DocTime .. (DocTime + follow_window))
    | summarize NovelRoutes = dcount(Route), Routes = make_set(Route, 20), Methods = make_set(CsMethod, 10),
                Statuses = make_set(ScStatus, 10), UserAgents = make_set(UserAgent, 5), Calls = count(),
                FirstCall = min(CallTime), LastCall = max(CallTime), DocFiles = take_any(DocFiles)
        by CIp, CsHost, DocTime
    | where NovelRoutes >= min_novel_routes
    | extend TimeGenerated = LastCall
    | project TimeGenerated, CIp, CsHost, DocFiles, DocTime, NovelRoutes, Routes, Methods, Statuses, UserAgents, Calls, FirstCall, LastCall
```
1. `ui_routes`: the per-app baseline. Normalised API routes (numeric and GUID segments become `{id}`) that at least 3 distinct clients called successfully between 14 and 1 days ago. Per `CsHost`, so each app has its own.
2. `docs`: clients that successfully (status below 400) downloaded a source map, Swagger / OpenAPI document, API docs, `config.json`, `env.js` or `runtime-config` in the last hour, and the time of the first download.
3. `calls`: API requests in the last hour whose normalised route is not in `ui_routes`.
4. Join per client and host; keep calls within 10 minutes after the first download; alert on at least 3 distinct such routes.

The file names are what Wiz's log shows (`.js.map`, `/assets/config.json`, `/env.js`, `/swagger/?format=openapi`) and the variants the owner listed (`swagger.json`, `openapi.json`, `/v2/api-docs`, `runtime-config`), which Wiz does not name.

### The per-app baseline of UI routes
The rule learns it from the app's own traffic, because that needs no change to the app: a route that several different clients call successfully is a UI route. Set `api_prefix` for apps whose API is not under `/api/`. Two other ways, not built:
- From the build: extract the API route strings the front-end contains (the same strings an attacker extracts) into a registry table, one row per app and route, and use that instead of the learned set. More accurate, and it needs a build step per app.
- From the OpenAPI spec: tag the operations the UI uses (for example `x-ui: true`) and load the tagged paths. Accurate only while the tags are maintained.

## Why this logic
- Config files alone cannot be the trigger: a real SPA fetches `config.json` and `env.js` on every page load. They are in the pattern because the second leg (at least 3 routes the UI does not use) separates the cases; a plain page load followed by UI routes did not alert (tested).
- Baseline ends one day ago so that an attacker's requests today cannot become "normal" for the rule. An attacker who is active for more than a day, from at least 3 clients, can.
- At least 3 distinct clients per baseline route: a route called by one tester is not "what the UI does". With fewer than 3 clients an app has an empty baseline and every API route is novel (a blind spot, below).
- 10 minutes and 3 routes: Wiz says routes were "called by name minutes after pulling the source maps". 10 minutes and 3 routes are this project's choice; loosening either made negatives match (tested).
- Alternative, D1's single decoy: lower false positives, but only catches agents that touch the decoy. This rule catches an agent that reads the map and calls any non-UI route, at a higher false-positive rate.
- Alternative, any non-baseline route without the document download: that is "new feature released", the main false positive.

## False positives
- A new front-end release in the last day: its new routes are not yet in the baseline. A client that also fetched `config.json` and calls 3 new routes will alert (config files are fetched by every real visitor). The baseline is 1 day behind, so this lasts about a day after a release.
- API clients that are not browsers (mobile apps, partner integrations, monitoring probes) that fetch a spec and call routes the web UI does not. Exclude by client IP or by app.
- Developers and testers with devtools open (source maps are fetched) who then try routes by hand.
- Many users behind one NAT address: the join is per IP.

## Tuning
- Negatives tested (9 scenarios): ordinary page load with config files then UI routes; source map then only 2 novel routes; novel routes before the document download; novel routes 15 minutes after the download; document download answered 404; novel routes without any download; download by one client and novel calls by another; non-API paths after the download; one novel route called three times. Each of eight clause loosenings made at least one negative match.
- Production: set `api_prefix` per app; exclude known API clients; consider raising `min_novel_routes` for apps with many routes behind admin screens.

## Test evidence
Run on 2026-11-07 in the Kusto emulator with timestamps shifted so the newest event is two minutes old (`rebase_time`; the query uses `ago()`); details in [tests/evidence.md](tests/evidence.md). 3 of 3 positive cases matched, 0 of 611 negative events. All samples are hand-written, including the baseline traffic. No recorded dataset is loaded.

## Blind spots
- Apps with a thin baseline: fewer than 3 clients per route means no route is "UI" and every API route is novel. The rule still needs the document download first, so it fires on any client that downloads one and calls 3 API routes. Tuning for low-traffic apps is untested.
- Documents behind authentication (401/403) are not counted as downloaded. That is the recommended hardening, and it removes the first leg of this rule; D1 and D3 remain.
- An agent that spaces its calls over more than 10 minutes, rotates source IPs between the download and the calls, or reuses routes that the UI also calls.
- Attack traffic that was already part of the baseline from at least 3 clients over days.
- Source maps blocked at the edge before the app log.

## References
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- docs/threats/artex-phase2-recon.md (claims checked).
- `schemas/reference/sentinel/AppServiceHTTPLogs.yaml` (Microsoft Learn table reference, fetched 2026-11-07).
