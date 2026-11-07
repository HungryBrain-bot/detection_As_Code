# Burst of AccessDenied across several AWS services from one principal

ATT&CK: T1580 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If an identity finds out what it is allowed to do by trying every API
call it knows, then within about a minute one principal produces many
authorization failures (`AccessDenied`, `UnauthorizedOperation`) across
several services. A person, or an application with a permissions bug,
fails a few calls on one or two services.

## Data sources
- `aws-cloudtrail` (cloud platform team): `AWSCloudTrail` in Sentinel (AWS S3 connector), management events with `ErrorCode`.
- No Azure branch: the Azure Activity log "doesn't typically capture read operations" (Microsoft Learn, fetched 2026-11-07), which are the calls an enumerator makes, and how it records an authorization failure was not found in the fetched pages. A Key Vault permission burst is a different log (`AzureDiagnostics`, see B4); not built here. See ADR 010.

## Detection logic
```kql
// D4: authorization-failure burst across services (detections/recon/D4-T1580-cloud-permission-burst/README.md)
    let bin_size = 1m;
    let min_denied = 20;
    let min_services = 4;
    // Principals that legitimately sweep every service (cloud security posture scanners). Fill per customer.
    let scanner_principals = dynamic([]);
    AWSCloudTrail
    | where ErrorCode contains "AccessDenied" or ErrorCode contains "UnauthorizedOperation"
    | where not(UserIdentityArn in (scanner_principals))
    | summarize Denied = count(), Services = dcount(EventSource), ServiceList = make_set(EventSource, 30),
                Actions = dcount(EventName), ActionList = make_set(EventName, 30), ErrorCodes = make_set(ErrorCode, 5),
                IPAddresses = make_set(SourceIpAddress, 10), UserAgents = make_set(UserAgent, 5),
                FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by UserIdentityArn, Window = bin(TimeGenerated, bin_size)
    | where Denied >= min_denied and Services >= min_services
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, UserIdentityArn, Window, Denied, Services, ServiceList, Actions, ActionList, ErrorCodes, IPAddresses, UserAgents, FirstSeen, LastSeen
```
1. Calls whose `ErrorCode` contains `AccessDenied` or `UnauthorizedOperation` (this covers `AccessDenied`, `AccessDeniedException` and `Client.UnauthorizedOperation`; the first and last are in the recorded data, the middle one is not).
2. Drop principals in `scanner_principals`.
3. Per principal ARN and 1-minute bin: denied calls, distinct services (`EventSource`) and actions, error codes, source IPs, user agents.
4. Alert on at least 20 denied calls across at least 4 services.

## Why this logic
- Services, not only counts: 30 denied calls on one service is a retry loop or a misconfigured application (tested negative); the recorded `cloudmapper` runs (at most 27 denied calls in a minute, all on one service) do not alert for this reason.
- Count, not only services: 19 denied calls across 5 services is below the threshold (tested), a developer working through a new permission set.
- Per principal: two principals with 15 each do not add up (tested).
- Denial codes only: throttling and other errors are not permission checks (tested: 30 `ThrottlingException`).
- Thresholds (20 calls, 4 services, 1 minute) are this project's reading of "within about a minute across several services" and were checked against recorded data: the recorded bursts the rule fires on have 73 to 612 denied calls over 4 to 36 services per minute.
- Alternative, GuardDuty or CloudTrail Insights: not queryable here; they are the better tools where enabled.
- Alternative, count only "enumeration" calls (`List*`, `Describe*`, `Get*`): would miss denied calls of other kinds (for example `AssumeRole`); not tested.

## False positives
- Cloud security posture scanners (cloudsploit, Prowler, ScoutSuite, CSPM products) run with narrow rights and sweep every service. The three recorded datasets are exactly this: every alert in them is the `cloudsploit` user. Excluded by principal through `scanner_principals`, empty by default; fill it per customer.
- Infrastructure-as-code runs and discovery tools in a new account before permissions are granted.
- Assumed-role sessions have a different ARN per session name; a burst across several sessions of one role is split across principals (blind spot).

## Tuning
- Negatives tested (7 scenarios): 19 denied across 5 services; 30 denied on one service; 30 denied on 3 services; 24 denied split over two bins 2 minutes apart; two principals with 15 each; 30 `ThrottlingException`; 30 successful calls across 6 services. Each of five clause loosenings (20 to 15 matched 3; 4 services to 1 matched 2; any error code matched 1; per-principal removed matched 1; 1-minute bin to 10 minutes matched 1) made at least one negative match.
- Production: fill `scanner_principals`; consider grouping by access key id or role ARN instead of session ARN.

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). Samples (hand-written): 2 of 2 positive cases matched, 0 of 193 negative events. Recorded: three Splunk attack_data CloudTrail sets (6,417 events): 11 rows, all the `cloudsploit` user; the ordinary users and `cloudmapper` did not alert. The recorded data is scanner tooling, not ARTEX.

## Blind spots
- A slower enumeration (under 20 denied calls per minute), one spread over several principals or access keys, or one that stays on the services it is allowed to call.
- Enumeration that mostly succeeds (a principal with broad read rights) produces no denials.
- Denied calls that CloudTrail does not log.
- Azure: not covered (see data sources). GCP: not covered.
- Whether ARTEX or any agent enumerates cloud permissions this way is not shown by the sources fetched (docs/threats/artex-phase2-recon.md); the rule detects the behavior, whoever does it.

## References
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07) (its detection list names "Unusual Mass Access Denied Activity"; it does not say for which platform).
- AWS, CloudTrail record contents, https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html (fetched 2026-11-07).
- Microsoft Learn, AWSCloudTrail table reference, https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail (fetched 2026-11-07).
- `schemas/reference/sentinel/AWSCloudTrail.yaml` (Azure-Sentinel repo, commit c0c2dc2).
- Recorded data: Splunk attack_data (Apache-2.0), commit b52ee68, `datasets/attack_techniques/T1580/` and `T1526/` (fetched 2026-11-07).
