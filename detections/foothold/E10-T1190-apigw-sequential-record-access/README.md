# One API Gateway client reads many record IDs in sequence or with many denials

ATT&CK: T1190 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

AWS port of [E1](../E1-T1190-sequential-record-access/) (ADR 014), on
API Gateway access logs. Same three reasons and thresholds; the record
ID comes from the path only.

## Hypothesis
Someone testing or exploiting broken object-level authorization (IDOR)
asks for many records by ID in a short time: in order (`/customers/1001`,
`1002`, ...), or at random with many 403/404 among the 200s, or pulling
far more data than a normal client. A client of the app reads a few of
its own records. API Gateway's access log has the path, status and
response size of every request.

## Data sources
- `aws-apigateway-access` (app platform team): API Gateway access logs
  in this project's format
  ([docs/components/apigateway-access-log.md](../../../docs/components/apigateway-access-log.md))
  in `AWSCloudWatch.Message`. Set `user` in the format to the
  authorizer's subject so clients behind one address are told apart.
- 14 days of the same log for the volume baseline.

## Detection logic
Query in [rule.yaml](rule.yaml).
1. Keep API Gateway access log lines (JSON with `apiId`,
   `requestTimeEpoch`, `status`).
2. Record ID: the number after a record noun in `path` (`customers`,
   `accounts`, `loans`, `orders`, `users`, `records`, `documents`,
   `invoices`, `statements`, ...). The pattern is per API, like E1's.
3. Client = source address + `user` (or `-`). Per domain, client and
   10-minute window of request time: distinct IDs, share of steps that
   go up by 1 to 5, share of 403/404, 200s, bytes.
4. Volume baseline: the 95th percentile of bytes per client per window
   for the domain, from 14 days to 1 day ago.
5. Alert at 20 or more distinct IDs and at least one of: 60 percent of
   steps in order; 30 percent 403/404 with at least one 200; bytes 10
   times the baseline.
6. `TimeGenerated` (possibly the ingestion time) picks the last hour and
   the baseline days; the request time orders and bins the requests.

## Why this logic
- Same logic and numbers as E1, so the App Service and API Gateway
  rules mean the same thing. E1's thresholds are this project's (ADR
  012); no source gives numbers for an IDOR walk.
- Every clause was shown to keep a negative out (evidence): 19 IDs; IDs
  in steps of 10 (paging); all 404 with no 200; ordinary sizes; IDs in
  order spread over 53 minutes; two users behind one address.
- Path only: API Gateway logs no query string (neither AWS variables
  page lists one), so E1's `?id=` branch is not possible here.

## False positives
- Back-office tools and exports that page through records by ID with
  a user's own token. Exclude their `user` values.
- Integration partners that sync many records (usually volume, not
  denials).
- A client retrying after an outage (many 5xx are not counted; many
  404s on deleted records may be).

## Tuning
- Negatives tested (6), listed above. Six loosenings each made one or
  more negatives match: IDs 20 to 19; step 5 to 10; 200 not required;
  volume ratio 10 to 1; window 10 minutes to 1 hour; client = address
  only.
- Production: fit `record_path` to each API's routes, and check the
  baseline has enough windows (`BaselineBins`) before trusting the
  volume reason.

## Test evidence
Run on 2026-11-21 in the Kusto emulator; [tests/evidence.md](tests/evidence.md).
3 of 3 positive cases matched (one per reason), 0 of 6 negative cases.
All samples are hand-written; no recorded API Gateway access log is
loaded.

## Blind spots
- Record IDs in the query string or the body (GraphQL, POST searches),
  and non-numeric IDs (UUIDs): not read. Random UUIDs make walking IDs
  impractical anyway, which is the point of using them.
- Slow walks (fewer than 20 IDs per 10 minutes), and walks spread over
  many addresses and users.
- `sourceIp` behind CloudFront is CloudFront's address; with no `user`
  in the format, many clients collapse into one (more false positives)
  or one attacker splits over edge addresses (misses).
- Requests API Gateway does not log (see D6), and APIs not behind API
  Gateway (ALB to containers: no reference schema here).

## References
- AWS, API Gateway access logging variables (REST and HTTP APIs), see
  docs/components/apigateway-access-log.md.
- Microsoft Learn, AWSCloudWatch table reference.
- E1 and its references (Zscaler 2026-10-14 recommendation on
  server-side authorization; Wiz 2026-10-22 on probing predictable
  identifiers; docs/threats/artex-phase4-foothold.md).
All fetched 2026-11-21 (AWS, Learn) or as dated in E1.
