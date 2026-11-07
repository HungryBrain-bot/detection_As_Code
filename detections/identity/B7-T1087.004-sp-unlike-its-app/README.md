# Service principal's Graph calls stop looking like its app (new client, enumeration, fix-and-retry)

ATT&CK: T1087.004, T1069.003, T1526 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If someone other than the app's own code drives a service principal
through Microsoft Graph, its app-only calls in one hour will show at
least two of: a client the app has not used in 14 days, listing two or
more directory collections, and a failed call that is changed and
retried successfully within 60 seconds.

## Data sources
- `entra-graph-activity` (identity team): `MicrosoftGraphActivityLogs`,
  14 days retained. Off by default; needs the diagnostic setting.
- Column list from Microsoft's table reference page, read through a
  summarising fetch tool (no Sentinel sample metadata exists for this
  table); the types are therefore less certain than for the other
  Entra tables.

## Detection logic
1. App-only calls: `ServicePrincipalId` set and `UserId` empty.
2. `Client` is the user-agent product token (`python-requests`,
   `kiota-dotnet`, ...), without version. `Endpoint` is the path with
   object ids and UPNs replaced by `{id}`.
3. Baseline per app (14 days to 1 hour ago): the set of clients.
4. Last hour per app:
   - NewClient: a client not in the baseline;
   - Enumeration: `GET` on two or more collection roots (`/users`,
     `/groups`, `/servicePrincipals`, `/applications`, `/directoryRoles`,
     `/devices`, `/roleManagement/directory/roleAssignments`, with any
     query string but no object id);
   - FixAndRetry: a 400, 403 or 404 followed within 60 s by a 2xx on the
     same method and endpoint with a different URI.
5. Alert when at least two are true. Only apps with a baseline are
   judged.

## Why this logic
- Two of three, not any one: each alone is ordinary somewhere. Sync and
  provisioning apps list users and groups every hour (tested negative);
  SDK upgrades change the user agent; well-written apps retry. The
  combination is what an exploring agent does and an app does not.
- Client family without version: a library upgrade
  (`kiota-dotnet/1.0` to `1.12`) is not a new client.
- Changed URI on retry: an identical retry is normal back-off; a
  *different* request after a failure is someone reading the error and
  adjusting (Microsoft's 28-80 s observations). 429 and 5xx are left
  out because they are throttling and service errors, not mistakes.
- Alternative: allowlist each app's expected endpoints. Precise, but
  needs a per-app inventory nobody keeps; the 14-day baseline is the
  automatic version of it.
- Alternative: alert on `python-requests` / `curl` / `Go-http-client`
  for any app. The recorded Splunk data shows why not: an app there
  reads `auditLogs/signIns` with `python-requests/2.28.1` as normal
  operation (it looks like a log-collection integration; that is a
  guess).

## False positives
- A developer or admin running a script with the app's secret
  (new client + enumeration). This is credential sharing and worth
  knowing about.
- A new version of the app that adds directory listing and switches
  SDK in the same release.
- Admin tooling apps (e.g. PowerShell modules acting as a service
  principal) whose use is irregular; they will have thin baselines.

## Tuning
- Negatives tested: sync app listing with its own SDK; new client doing
  single-object reads and a fix after 85 s (outside the window); a
  delegated (user) session with `python-requests` listing users and
  groups; an app with no baseline. Each matched when its clause was
  removed (threshold to 1, window removed, app-only filter removed,
  baseline join made optional).
- Production: exclude known admin-tooling apps; consider adding
  `/subscriptions` style ARM enumeration if ARM read logs become
  available (they are not in `AzureActivity`, which logs writes).

## Test evidence
Run on 2026-11-07 in the Kusto emulator with `rebase_time` (the query
uses `ago()`); details in [tests/evidence.md](tests/evidence.md).
2 of 2 positive cases matched (18 events), 0 of 27 negatives. All
samples are hand-written. The 27 recorded Graph activity records (16
app-only, from 5 apps, clients `python-requests`, `kiota-dotnet` and
empty) returned 0 rows: they span about 70 seconds, so no app has a
baseline and none is judged. That is not evidence about false
positives.

## Blind spots
- An agent that sets its user agent to the app's SDK string and avoids
  listing (reads only objects it already knows): at most one signal.
- Enumeration through Azure Resource Manager, Key Vault or storage
  rather than Graph: not in this table. ARM read operations are not in
  the Activity log [Likely; not checked here].
- Apps with less than 14 days of history, or none in the window.
- Tenants without the Graph activity diagnostic setting.
- An attacker who stays more than 14 days becomes the baseline.

## References
- Microsoft, "Threat actors use agentic AI tooling to find and abuse
  exposed secrets", 2026-11-05 (fetched 2026-11-07).
- Microsoft Learn, MicrosoftGraphActivityLogs table reference
  (fetched 2026-11-07).
- Recorded Graph activity: Splunk attack_data
  `azure_ad_privileged_graph_perm_assigned.log` @ b52ee68.
