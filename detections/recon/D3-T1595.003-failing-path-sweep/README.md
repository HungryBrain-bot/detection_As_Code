# One client tries dozens of distinct paths in minutes, mostly failing

ATT&CK: T1595.003 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If a client is guessing routes, or walking routes it extracted from a
script or spec, then within a few minutes one source IP asks for dozens
of distinct paths on one host and most answers are 401, 403 or 404.

## Data sources
- `app-service-http` (app platform team): `AppServiceHTTPLogs`.
- Same coverage limits as D1: App Service only.

## Detection logic
```kql
// D3: path sweep with mostly 401/403/404 (detections/recon/D3-T1595.003-failing-path-sweep/README.md)
    let bin_size = 5m;
    let min_distinct_paths = 30;
    let min_error_share = 0.7;
    AppServiceHTTPLogs
    | summarize Requests = count(), DistinctPaths = dcount(tolower(CsUriStem)),
                Errors = countif(ScStatus in (401, 403, 404)),
                Statuses = make_bag(pack(tostring(ScStatus), 1)), UserAgents = make_set(UserAgent, 5),
                SamplePaths = make_set(CsUriStem, 10), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by CIp, CsHost, Window = bin(TimeGenerated, bin_size)
    | extend ErrorShare = round(todouble(Errors) / Requests, 2)
    | where DistinctPaths >= min_distinct_paths and ErrorShare >= min_error_share
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, CIp, CsHost, Window, Requests, DistinctPaths, Errors, ErrorShare, UserAgents, SamplePaths, FirstSeen, LastSeen
```
1. Per client IP, host and 5-minute bin: requests, distinct paths (case-insensitive), responses with 401, 403 or 404, sample paths, user agents.
2. Alert on at least 30 distinct paths and at least 70 percent of requests answered 401, 403 or 404.

## Why this logic
- Distinct paths, not request count: a retry loop on 10 paths is not a sweep (tested: 100 requests, 10 paths, all 404).
- Error share, not error count: a user or crawler that requests 60 distinct real files (mostly 200) is not a sweep (tested: 30 percent errors).
- 401, 403 and 404 only: 500 and 502 mean the server is failing, not that the client is guessing (tested: 60 paths all 5xx).
- Per client, not per host: 20 paths each from two clients is not one sweep (tested).
- Thresholds are this project's. Wiz reports "more than 60 variations of SSO routes with this payload in just two minutes", about one request per second, and a baseline "not found" probe (`GET /zzz-nonexistent-xyz123`) before each fuzzing run; it gives no error-rate figures. 30 paths in 5 minutes catches the Wiz rate with room; 70 percent is a guess.
- Alternative, per-minute bins: lower latency, more false positives from short bursts; 5-minute bins are fixed windows, so a sweep split across a bin edge can fall under 30 in each (blind spot below).
- Alternative, WAF or rate-limit signals: not in the data this project has.

## False positives
- Authorised scanners, pentests and your own link checkers: exclude by IP (not built in; add a `known_testers` let as in D1 when a customer has some).
- Search-engine and monitoring crawlers walking old URLs after a redesign (many 404s, many paths).
- Broken front-end releases requesting many missing assets (this is one client IP per user; many users behind one NAT address can add up).

## Tuning
- Negatives tested (7 scenarios): retry loop on 10 paths; 60 paths with 30 percent errors; 25 paths all failing; 60 paths with 60 percent errors; two clients with 20 paths each; 60 paths all 5xx; 40 failing paths spread over 24 minutes. Each of five clause loosenings (paths 30 to 20, share 0.7 to 0.5, distinct to count, per-client removed, 5xx counted) made at least one negative match.
- Production: allowlist authorised scanners; check what share of your hosts' traffic the rule would have flagged before turning on alerting.

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). 2 of 2 positive cases matched, 0 of 385 negative events. All samples are hand-written. No recorded dataset is loaded.

## Blind spots
- A slow sweep (fewer than 30 paths in any 5-minute bin) or one spread over many source IPs.
- A sweep split across a bin edge.
- A sweep whose answers are mostly 200 (for example an app that returns its index page for every path) or 301/302.
- Clients behind a proxy where `CIp` is the proxy.

## References
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- MITRE ATT&CK T1595.003 Wordlist Scanning (bundle fetched 2026-11-07).
- docs/threats/artex-phase2-recon.md (claims checked).
- `schemas/reference/sentinel/AppServiceHTTPLogs.yaml` (Microsoft Learn table reference, fetched 2026-11-07).
