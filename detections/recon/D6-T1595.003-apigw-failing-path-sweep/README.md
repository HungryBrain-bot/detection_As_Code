# One client tries dozens of distinct API Gateway paths in minutes, mostly failing

ATT&CK: T1595.003 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

AWS port of [D3](../D3-T1595.003-failing-path-sweep/) (ADR 014), on API
Gateway access logs.

## Hypothesis
A tool that guesses API routes, or walks routes extracted from a spec or
a script, requests many distinct paths in a short time and most of them
fail (401, 403, 404). Clients using an API through its app call few
distinct paths and mostly get 2xx. On API Gateway, the access log
records each request's path, status and source address.

## Data sources
- `aws-apigateway-access` (app platform team): API Gateway access logs
  in this project's JSON format
  ([docs/components/apigateway-access-log.md](../../../docs/components/apigateway-access-log.md)),
  CloudWatch Logs -> S3 (Microsoft's subscription Lambda) -> Sentinel
  `AWSCloudWatch`, one log line per `Message`. Every API stage to cover
  needs access logging on with that format. A stage logging another
  format is skipped, not misread.
- No vendor format exists: API Gateway lets each stage choose its own.
  That is why the format is part of this project.

## Detection logic
Query in [rule.yaml](rule.yaml).
1. Keep `AWSCloudWatch` rows whose `Message` is a JSON object with
   `apiId`, `requestTimeEpoch` and `status` (other CloudWatch logs in
   the same table are skipped).
2. Time is `requestTimeEpoch` (milliseconds; seconds accepted, since
   the HTTP API page gives no unit), not `TimeGenerated`, which may be
   the ingestion time.
3. Per source address, API domain and 5-minute window: requests,
   distinct lower-cased paths, and the share answered 401/403/404.
4. Alert at 30 or more distinct paths with a 70 percent or higher error
   share. Same thresholds as D3.

## Why this logic
- Same thresholds as D3, so the Azure and AWS rules mean the same
  thing; no source gives an error share for an agent's sweep. Wiz's
  burst (more than 60 SSO route variations in two minutes) is above 30.
- Per address and domain: a sweep split over two addresses, or over two
  APIs, of 20 paths each did not alert; dropping either key made it
  alert (evidence).
- `path` (what was requested), not `routeKey` / `resourcePath` (the
  route that matched): unmatched requests have no route, and distinct
  requested paths are what a sweep produces.
- 401/403/404: REST APIs answer an unknown path with 403 ("Missing
  Authentication Token") [Likely, not confirmed on a fetched AWS page],
  HTTP APIs with 404, and authorizers with 401/403.

## False positives
- API contract tests, fuzzers and DAST scans you run yourself.
- A client with a stale route list after an API version change (many
  404s on old routes). The 30-path threshold keeps small cases out.
- A partner integration retrying many record paths that it may not
  read (403). If that is normal, raise `min_distinct_paths` for that
  domain.

## Tuning
- Negatives tested (6): 29 failing paths; 40 paths with half failing;
  40 failing paths over two addresses; 40 over 20 minutes; 40 over two
  API domains; 40 JSON log lines from another source that mention
  `apiId` but have no `status`. Five loosenings made a negative match
  (evidence). The `status` filter was not shown to bite: those lines
  have no status, so they never count as errors either; it keeps them
  out of the request counts.
- Production: measure distinct paths per address per 5 minutes for two
  weeks and set the threshold above its peak for each API.

## Test evidence
Run on 2026-11-21 in the Kusto emulator; [tests/evidence.md](tests/evidence.md).
1 of 1 positive case matched, 0 of 6 negative cases. All samples are
hand-written. No recorded API Gateway access log is loaded.

## Blind spots
- Requests API Gateway does not write to the access log. Whether a
  request to a path with no matching resource, a throttled request or a
  request WAF blocked appears there was not found on the AWS pages read.
  If unmatched paths are not logged, the rule sees only sweeps over
  routes that exist (and fail authorization).
- `sourceIp` is "the immediate TCP connection": behind CloudFront it is
  CloudFront's address, and a distributed sweep spreads over CloudFront
  edge addresses. Per-address counting then misses it.
- A slow sweep (under 30 paths per 5 minutes), or one spread over many
  addresses (D3 has the same gap).
- Stages without access logging, or with another format.
- The pipeline (Lambda, S3, connector) was not run; `TimeGenerated`
  could lag the request by the Lambda's delivery delay, and a 1-hour
  query period could miss a late batch.

## References
- AWS, "Variables for access logging for API Gateway" and "Customize
  HTTP API access logs" (`$context.path`, `status`,
  `identity.sourceIp`, `requestTimeEpoch`), see
  docs/components/apigateway-access-log.md for the URLs and quotes.
- Microsoft Learn, AWSCloudWatch table reference and "Connect Microsoft
  Sentinel to Amazon Web Services" (CloudWatch logs via a Lambda).
- Azure-Sentinel c3361d9, `DataConnectors/AWS-S3/CloudWatchPushBasedLambdaFunction.py`.
- D3 and its references (Wiz, 2026-10-22).
All fetched 2026-11-21.
