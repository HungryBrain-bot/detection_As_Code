# App Service publishing login (Kudu, FTP, Web Deploy) by an identity outside the pipeline

ATT&CK: T1078.004 · Severity: Medium · Status: experimental · Tier: targeted · Targets: sentinel

## Hypothesis
If someone other than the deployment pipeline logs in to an App Service's
publishing endpoints (the Kudu/SCM site, FTP or Web Deploy), then
`AppServiceAuditLogs` records a login whose user is not one of the
pipeline's identities. For an app that is only ever deployed by a
pipeline, any such login is unexpected.

## Data sources
- `app-service-audit` (app platform team): `AppServiceAuditLogs`. Columns
  and types from Microsoft's table reference (fetched 2026-11-07): `User`
  ("Username used for publishing access"), `UserDisplayName` ("Email
  address of a user in case publishing was authorized via AAD
  authentication"), `UserAddress`, `Protocol` ("Authentication protocol"),
  `OperationName`, `_ResourceId`.
- Prerequisite: the `AppServiceAuditLogs` diagnostic setting is on for
  each app. Microsoft describes the log as "Login activity via FTP and
  Kudu"; the basic-auth page says "All successful and attempted logins are
  logged", the table page says it covers users who "successfully log on".
  Which of the two is right was not checked.
- What this table does not have: the commands run in Kudu. No Microsoft
  page read for this rule documents a log of Kudu command execution, so
  the rule detects the login that comes before it, not the commands.

## Detection logic
```kql
// see rule.yaml for the full query
```
1. Optionally restrict to the apps listed in `pipeline_only_apps`
   (resource id substrings); empty means every app.
2. Drop logins whose `User` or `UserDisplayName` (lower case) is in
   `pipeline_identities`.
3. Report what is left with the app name, protocol, user and client IP.

## Why this logic
- Allowlist of pipeline identities, not a list of bad ones: for an app
  deployed only by a pipeline, the set of legitimate publishing identities
  is short and known; anything else is worth a look.
- No `Protocol` filter: only "FTP" is shown as a value on the pages read;
  the strings for Kudu and Web Deploy are not documented, so filtering on
  them would rest on a guess. The rule alerts on every protocol.
- Alternative, `AzureActivity` for the publishing-credentials read
  (`publishxml` / list credentials): catches the step before the login,
  but the operation names were not verified for this rule; parked.
- Alternative, `AppServiceHTTPLogs` for requests to the SCM host: no
  Microsoft page read says SCM requests appear in that table.

## False positives
- Developers or operators who log in to Kudu to troubleshoot. If that is
  allowed, add their identities, or scope `pipeline_only_apps` to the apps
  where it is not.
- A new pipeline identity (renamed service connection, new deployment
  slot credential) before it is added to the list.
- Defaults: `pipeline_identities` is empty, so out of the box every
  publishing login alerts, including the pipeline's own. Fill it before
  turning alerting on.

## Tuning
- Fill `pipeline_identities` (lower case) with the publishing user names
  (for app-level credentials, the `$<app>` form) and the Entra identities
  the pipeline uses.
- Disabling basic authentication for SCM and FTP (Microsoft's
  "Disable Basic Authentication for Deployment") removes the
  shared-credential path and leaves Entra logins, which carry
  `UserDisplayName`.
- No samples have been run.

## Test evidence
Not run. No positive or negative samples exist and the query has not been
executed in the Kusto emulator; no recorded `AppServiceAuditLogs` data is
available. The rule is `experimental`, so it is deployed disabled. See
[tests/evidence.md](tests/evidence.md).

## Blind spots
- Command execution through Kudu by an identity on the allowlist (a
  stolen pipeline credential looks like the pipeline).
- Changes made through the Azure control plane (ARM) rather than the
  publishing endpoints.
- Apps without the diagnostic setting.
- If the table records only successful logins, failed attempts are not
  seen.

## References
- Microsoft Learn, AppServiceAuditLogs table reference, https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceauditlogs (fetched 2026-11-07)
- Microsoft Learn, App Service monitoring data reference, https://learn.microsoft.com/en-us/azure/app-service/monitor-app-service-reference (fetched 2026-11-07)
- Microsoft Learn, Kudu service overview, https://learn.microsoft.com/en-us/azure/app-service/resources-kudu (fetched 2026-11-07)
- Microsoft Learn, Disable Basic Authentication for Deployment, https://learn.microsoft.com/en-us/azure/app-service/configure-basic-auth-disable (fetched 2026-11-07)
- docs/threats/artex-phase4-foothold.md; ADR 012
