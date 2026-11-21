# AWS IAM user or role stops looking like its workload (new client, new discovery calls, fix-and-retry)

ATT&CK: T1087.004, T1526, T1580 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

AWS port of [B7](../B7-T1087.004-sp-unlike-its-app/) (ADR 013).

## Hypothesis
Production code calls the same APIs with the same SDK every day. When a
person or an agent drives a stolen key, it asks "who am I" and "what is
here", uses a different client, and fixes failed calls by trying again
with different parameters. Two of those three in one hour, against the
principal's own 14-day history, is unlike the workload.

## Data sources
- `aws-cloudtrail` (cloud platform team): `AWSCloudTrail`.

## Detection logic
1. Calls by `IAMUser` or `AssumedRole` identities, not made by an AWS
   service on their behalf (`UserIdentityInvokedBy` empty). Principal as
   in B16 (role ARN for role sessions).
2. Client: the user-agent family (text before the first `/`, leading
   `[` removed: some recorded SDK agents are logged in brackets).
3. Baseline (before the last hour): clients and `service:API` pairs.
4. In the last hour, three signals:
   - **NewClient**: a client family not in the baseline.
   - **Enumeration**: at least 5 discovery calls (`List*`, `Describe*`,
     `GetCallerIdentity`, `GetAccountAuthorizationDetails`) the
     principal never made in the baseline.
   - **FixAndRetry**: a failed call (not throttling) followed within 60
     seconds by a successful call to the same API with different
     request parameters.
5. Alert when at least two signals are true.

## Why this logic
- Two of three, as B7: each signal alone happens in normal operation
  (an SDK change, a new feature that lists resources, a retry). With
  "one is enough", six of eight negatives matched.
- New discovery calls, not all discovery calls: workloads call
  `Describe*` all day; what matters is the ones this principal never
  made. Threshold 5: with 4, the "4 new calls" negative matched.
- Throttling excluded and parameters must differ: SDKs retry throttled
  and transient failures themselves; that is not someone fixing a call.
  Both clauses were shown to bite.
- 60 seconds: Microsoft saw retries "about 28, 60 and 80 seconds" after
  failures on Azure; this keeps B7's window. With 120 s the 90-second
  negative matched.

### How this differs from D4
D4 (recon) fires on 20 or more denied calls across 4 or more services in
one minute, for any principal, with no history. It catches a loud
permission sweep. B17 needs history and fires on quieter behaviour: a
handful of new, mostly successful discovery calls plus a new client or
a corrected retry. A loud sweep by a principal with history can fire
both; that overlap is accepted (one is "a burst of denials", the other
"unlike itself").

## False positives
- An engineer debugging with the workload's own key from the CLI (new
  client plus new calls). That is a finding: production keys should not
  be used by hand.
- A deployment that adds a feature and changes SDK in the same hour.
- Infrastructure-as-code tools running under a workload role.

## Tuning
- Negatives tested (8): new client only; new discovery calls only; new
  client plus 4 new discovery calls; new client plus a throttled call
  followed by a different call; new client plus a retry after 90 s; new
  client plus the same request succeeding again; a brand-new user with
  no baseline; calls made by CloudFormation for the user. Each was shown
  to match when its clause was loosened (evidence).

## Test evidence
Run on 2026-11-21 in the Kusto emulator; details in
[tests/evidence.md](tests/evidence.md). 2 of 2 positive cases matched,
0 of 8 negative cases. All samples hand-written. Recorded CloudTrail
data (6,417 events, timestamps rebased): 0 rows. The scanner users in
it (`cloudsploit`, `cloudmapper`) have no history before their first
burst, so B17 cannot judge them (D4 alerts on `cloudsploit`).

## Blind spots
- A principal with no history (new user, new role, a decoy): the
  inner join drops it. This is how the recorded scanners pass.
- An attacker who uses the workload's own SDK and only APIs it already
  calls.
- Discovery through APIs not named `List*` / `Describe*` (many `Get*`
  calls). Only two `Get*` calls are included.
- Read-only calls that CloudTrail does not log, or data events.
- Log Analytics engine not used (ADX emulator only).

## References
- AWS, "CloudTrail userIdentity element" (invokedBy, sessionIssuer) and
  "CloudTrail record contents" (userAgent for AWS-originated events),
  fetched 2026-11-21 (URLs in B14).
- Microsoft, 2026-11-05 (retry timings), via B7.
