# Request to a decoy API route, seen by AWS WAF

ATT&CK: T1595, T1594 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

AWS port of [D1](../D1-T1595-decoy-route-hit/) (ADR 014). Same decoy
routes, same registry rows; the request is read from AWS WAF's log
instead of App Service's.

## Hypothesis
If a tool reads an app's published OpenAPI spec or JavaScript bundle and
requests the routes it finds, it will request a route that exists only
as bait. When the app runs on AWS behind AWS WAF (CloudFront, an
Application Load Balancer, an API Gateway REST API, AppSync, Cognito and
the other resource types WAF protects), WAF logs that request whether it
allows or blocks it. Any request to a decoy route means someone is
working from the published map.

## Data sources
- `aws-waf` (app platform team): `AWSWAF`, through Sentinel's AWS S3 WAF
  connector. The web ACL must log to S3 and must sit in front of the app
  that publishes the decoy. WAF logs every request the web ACL evaluates
  unless a logging filter drops some; a filter that keeps only blocked
  requests hides allowed decoy hits.
- `honeytoken-registry` (detection team): `Honeytoken_CL` rows with
  `TokenType` = `DecoyRoute`, exactly as for D1. Re-sent at least
  hourly; if not, the rule matches nothing (fails silent).
- Not covered: API Gateway HTTP APIs (AWS WAF's list of protected
  resource types names only "Amazon API Gateway REST API"); apps with no
  web ACL in front.

## Detection logic
Query in [rule.yaml](rule.yaml).
1. Read the registry; lower-case each route and drop a trailing `/`.
2. Read the request from the `HttpRequest` column (`clientIp`, `uri`,
   `args`, `headers`, `httpMethod`, `host`), not from the top-level
   `ClientIp` / `Uri` columns.
3. Compare the path, lower case, without a trailing slash, with each
   decoy. Also compare it with its first segment removed, because an API
   Gateway REST path can start with the stage (`/prod/...`).
4. Any action counts (ALLOW, BLOCK, CAPTCHA, CHALLENGE).
5. One row per client address and route, with methods, actions, user
   agents, hosts, query strings, WAF source (CF / ALB / APIGW and its
   id) and the planted location.

## Why this logic
- `HttpRequest`, not the top-level columns: in Microsoft's ingested
  sample of this table (200 rows, Azure-Sentinel), `ClientIp`, `Uri`,
  `HttpMethod`, `Headers` and `Args` are empty on every row and the
  request is in `HttpRequest`; Microsoft's ASIM parser for the table
  reads `HttpRequest` too. A rule on `Uri` would match nothing there.
- Any action: WAF may block the request (a rate rule, a bot rule); the
  requester still followed the map.
- No status: WAF does not see the origin's answer. `ResponseCodeSent`
  is only for WAF's own custom responses (AWS: "The response code sent
  with a custom response"; Microsoft's parser: only "when a custom block
  response is configured"). D1's "a 404 is still a hit" holds trivially.
- Exact path match. Loosening it to `has_any` made two negatives match
  (a real route `...export-customers-v2`, and the decoy under two extra
  segments).
- One stage segment stripped, not any prefix: stripping everything up to
  `/api/` made the two-extra-segments negative match.
- The query string is not searched: a search for the decoy's path is
  not a request to it. Searching `args` made that negative match.

## False positives
- Your own API test tools, contract tests and DAST scanners that call
  every route in the spec: list their addresses in `known_testers`.
- A developer who read the spec and tried the route.
- A crawler that follows links in a published spec.

## Tuning
- Negatives tested (5): a real route that starts with the decoy's name;
  the decoy path under two extra segments; the decoy only in the query
  string; a real route that is a prefix of the decoy; a browser
  downloading the bundle that carries the decoy. Three loosenings made
  at least one match each (evidence).
- Use routes that look valuable and are not near a real route's name.

## Test evidence
Run on 2026-11-21 in the Kusto emulator; [tests/evidence.md](tests/evidence.md).
3 of 3 positive cases matched, 0 of 5 negative cases. All samples are
hand-written. Microsoft's 200-row ingested WAF sample returned 0 rows
(no decoy in it); it shows only that the query runs on rows shaped as
the connector writes them.

## Blind spots
- Client address: `clientIp` is the address that reached WAF. With WAF
  on an ALB behind CloudFront, that is CloudFront's address, not the
  requester's. Put the web ACL on the CloudFront distribution, or read
  `X-Forwarded-For` from the headers in triage.
- Whether WAF's `uri` for an API Gateway REST API carries the stage was
  not found on the AWS pages read; the rule accepts both forms.
- A logging filter, or WAF sampling the log, drops requests.
- Decoy route names that the tool decodes or rewrites (e.g. URL-encoded
  segments) are not normalised.
- Everything D1 lists: a tool that reads the spec but does not call the
  decoy, and a decoy route found by no one.

## References
- AWS, "Log fields for web ACL traffic" (`uri` "The URI of the
  request.", `args` "The query string.", `clientIp`, `httpSourceName`
  CF / APIGW / ALB / APPSYNC / COGNITOIDP / APPRUNNER / VERIFIED_ACCESS,
  `responseCodeSent` "The response code sent with a custom response."),
  https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
- AWS, "What are AWS WAF, AWS Shield Advanced, and AWS Firewall
  Manager?" (resource types WAF protects),
  https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html
- Microsoft Learn, AWSWAF table reference,
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awswaf
- Azure-Sentinel, commit c3361d9: `Sample Data/Tables/AWSWAF/metadata.json`
  (column types), `Sample Data/ASIM/AWS_WAF_WebSession_AWSWAF_IngestedLogs.csv`
  (ingested sample), `Parsers/ASimWebSession/Parsers/ASimWebSessionAWSWAF.yaml`
  (read directly with git).
- D1 and its references (Wiz, 2026-10-22).
AWS and Learn pages fetched 2026-11-21 through a fetch tool.
