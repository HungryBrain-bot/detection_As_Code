# 014. AWS and API Gateway ports of ARTEX Phases 2-4 (D5, D6, B18, E10-E12)

## Status
Accepted (2026-11-21)

## Context
ADR 013 ported Phase 1 (credential sourcing) to AWS CloudTrail as
B14-B17. On 2026-11-21 the owner asked, in the project thread, to
"create the same for all the phases considering aws based scenarios and
api scenarios". The coordinator's note asked for one PR per phase, to
port only what is missing on AWS, and to skip any port that would be a
guess or a duplicate.

Each Phase 2-4 rule was checked for what makes it Azure-specific: the
table it reads (App Service, Entra, Okta, Defender, App Service audit)
or only the platform its samples assume. A port was built only where
an AWS log with a vendor-documented (or, for API Gateway, a
self-defined and documented) shape records the same behaviour.

No fetched source shows ARTEX, or the agents in the Microsoft, Wiz,
CrowdStrike, Zscaler or Recorded Future reports, acting on AWS. These
rules detect the same behaviour on AWS; they are not evidence that
those actors do it there.

## Decision

### What was ported
| Original | Port | AWS log | Why this log |
|---|---|---|---|
| D1 decoy route | **D5** | AWS WAF (`AWSWAF`) | WAF sits in front of CloudFront, ALB, API Gateway REST, AppSync and Cognito; one log covers most AWS web front doors. No origin status is needed (any request to a decoy counts). |
| D3 path sweep | **D6** | API Gateway access log (`AWSCloudWatch`) | Needs the response status; WAF does not record it. API Gateway is the API scenario the owner named. |
| B8 Entra spray | **B18** | CloudTrail `ConsoleLogin` and IAM Identity Center `CredentialVerification` | The two places a password is checked and recorded by AWS itself. One rule, since both are the same log source. |
| E1 IDOR walk | **E10** | API Gateway access log | Path, status and response size per request. |
| E8 App Service publishing login | **E11** | CloudTrail `StartSession`, `SendSSHPublicKey`, `SendSerialConsoleSSHPublicKey` | AWS's back door to a server through the control plane; a counterpart, not a translation (E8 is a deployment channel). |
| E9 request-capture egress (Defender) | **E12** | Route 53 Resolver query log (`AWSRoute53Resolver`) | DNS names from every VPC workload, sensor or not; flow logs have no names. |

### What was not ported, and why
| Original | Reason |
|---|---|
| D2 docs-then-novel-routes | The documents (bundles, source maps) are usually served from S3 / CloudFront and the API calls from API Gateway: two logs, and WAF has no status to say a download succeeded. A port would join two new sources on guessed keys. Parked. |
| D4 | Already AWS (CloudTrail). |
| B9 Okta spray | Okta is not AWS; B9 already covers Okta in front of AWS. |
| B10 several login flows | On AWS the only flows recorded with a password are the two in B18; the rest of B10 (ROPC, legacy, SSPR) has no AWS counterpart. A B10 port would be B18 again. |
| B11 recovery for many users | No IAM Identity Center password-reset event is in AWS's sign-in event list (fetched). Amazon Cognito: AWS says it "records `UserSub` but not `UserName`" and its examples show the user name as `HIDDEN_DUE_TO_SECURITY_REASONS`, so "many users" cannot be counted for unknown users, and no `ForgotPassword` event example was found. A rule would be a guess. |
| B12 legacy / ROPC | No AWS sign-in has a legacy-protocol path. Cognito's `USER_PASSWORD_AUTH` flow is the nearest; whether CloudTrail tells it apart from SRP was not found. |
| B13 OAuth / JWT tampering | B13 reads `AppAuthEvent_CL`, which the app writes; it already works for an app on AWS. API Gateway's `$context.authorizer.error` holds the authorizer's message, but the messages for a bad signature or `alg: none` were not found on AWS's pages. Parked. |
| Cognito user-pool spray | Same field problem as B11 (no user name; failure shape of `InitiateAuth` not documented on the pages read). Cognito's threat-protection user activity logs have more, but are a paid feature with an unverified field list. Parked. |
| E2-E6 endpoint rules | Defender for Endpoint and Sysmon run on EC2 unchanged; the same rules apply. A copy would be a duplicate. |

### Design points
1. **API Gateway access log format.** API Gateway has no fixed format:
   each stage's owner writes one from `$context` variables. This
   project defines one JSON format
   ([docs/components/apigateway-access-log.md](../components/apigateway-access-log.md))
   for D6 and E10, as it defined `AppAuthEvent_CL` (ADR 011) and
   `IpAsn_CL` (ADR 013). Every variable used is on AWS's REST or HTTP
   API variables page (fetched). The log reaches Sentinel as
   `AWSCloudWatch.Message` through a CloudWatch-to-S3 Lambda
   (Microsoft's, Azure-Sentinel c3361d9, which writes each event's
   `message` as one line) and the AWS S3 connector. New log source
   `aws-apigateway-access` (app platform team).
2. **Request time from the message.** Microsoft's Lambda drops the
   CloudWatch timestamp and Learn says `AWSCloudWatch.TimeGenerated`
   falls back to the ingestion time, so D6 and E10 bin on
   `requestTimeEpoch` (milliseconds; seconds accepted, since the HTTP
   API page gives no unit). E10 still selects its last hour and baseline
   days by `TimeGenerated`, which is what a Sentinel scheduled rule
   filters on.
3. **AWSWAF request column.** In Microsoft's 200-row ingested sample the
   top-level `ClientIp`, `Uri`, `HttpMethod`, `Headers` and `Args` are
   empty on every row; the request is in `HttpRequest`, which
   Microsoft's ASIM parser also reads. D5 reads `HttpRequest`. The
   sample is loaded as D5's recorded background.
4. **Hidden user names (B18).** AWS writes `HIDDEN_DUE_TO_SECURITY_REASONS`
   for unknown console user names and Identity Center user names; they
   are not counted as accounts (as B8 does not count 50034). The
   Identity Center user name is taken from the `CredentialChallenge`
   with the same `AuthWorkflowID`, since AWS writes it there.
5. **E11 admin list.** A per-customer list of role and user ARNs allowed
   to open shells; empty means every opening alerts (as E8's pipeline
   list). `SendCommand` is left out on purpose (patching path).
6. **E12 domain list.** E9's list, already checked on each service's
   page; trailing dots stripped because whether the connector keeps
   them was not found.
7. **Numbering and status.** D5-D6, B18, E10-E12 follow the highest
   number in each track. All `status: test`, `targeted`, Sentinel only:
   unlike E1-E9, these have positive and negative samples and engine
   runs.
8. **Harness.** `from_cloudtrail` maps `ResponseElements`,
   `AdditionalEventData` and `ServiceEventDetails` (JSON text);
   `AWSWAF`, `AWSCloudWatch` and `AWSRoute53Resolver` rows load as they
   are; a `sentinel-table-csv` dataset format reads Microsoft's
   ingested-sample CSVs (day-first time column, empty cells dropped,
   dynamic JSON parsed); dataset paths are URL-quoted (the
   Azure-Sentinel path has a space). Five new recorded datasets: the
   WAF sample (MIT) and four Splunk attack_data CloudTrail sets
   (Apache-2.0).
9. **One PR, not three.** The coordinator suggested one PR per phase.
   This thread may push to one branch only, so the three phases are
   three commits in one PR, stacked on PR #13 (Phase 1 AWS port).

## Consequences
- 6 rules added: 42 in total (D1-D6, B1-B18, E1-E6, E8-E12, A1-A4,
  C1-C3).
- Recorded evidence: B18 caught the recorded console spray (31 IAM
  users, one address, Splunk attack_data) and nothing in three other
  recorded sign-in sets; E11 caught the recorded Instance Connect set
  (12 key pushes by one role). D5 returned 0 rows on Microsoft's WAF
  sample (no decoy in it). D6, E10 and E12 rest on hand-written samples
  only: no public recorded API Gateway access log or Route 53 Resolver
  log was found.
- Three new log sources to confirm per customer (`aws-waf`,
  `aws-apigateway-access`, `aws-route53-resolver`), plus a per-stage
  access log format for API Gateway that someone must set.
- Not verified: the AWS WAF, Route 53 and CloudWatch connectors (not
  run); whether API Gateway writes unmatched, throttled or WAF-blocked
  requests to the access log; whether WAF's `uri` carries the API
  Gateway stage; whether `QueryName` keeps the trailing dot; any IAM
  Identity Center event as AWS writes it (no recorded one; samples
  follow AWS's example, and AWS's text and example disagree on where
  `CredentialType` is); that `SendSerialConsoleSSHPublicKey` is logged
  to CloudTrail; any false-positive rate; Log Analytics (ADX emulator
  only).

## Alternatives considered
- **One rule per web log (WAF, ALB, CloudFront, API Gateway) for each of
  D1-D3:** more coverage, four times the rules, and ALB / CloudFront
  have no Sentinel table here. One log per behaviour, chosen by what the
  behaviour needs (any request for D5; status for D6 and E10).
- **A project-defined `ApiGatewayAccess_CL` table** instead of
  `AWSCloudWatch.Message`: typed columns, but a custom ingestion
  pipeline (DCR) to build; `AWSCloudWatch` uses Microsoft's connector
  and Lambda as they are.
- **GuardDuty findings** (e.g. for E12's DNS case, or B18): good where
  enabled, but not every customer runs GuardDuty and which findings
  exist today was not checked.
