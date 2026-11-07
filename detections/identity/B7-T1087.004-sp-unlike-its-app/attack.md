# Directory discovery through Microsoft Graph with a stolen app credential (T1087.004, T1069.003, T1526)

## What the attack is
After signing in as a service principal with a stolen secret, the
attacker (or an agent working for one) does not know what the app is
for or what it can reach. It finds out by asking: listing users,
groups, service principals, applications and role assignments through
Microsoft Graph, and correcting its requests when they fail. The app's
own code never does this; it makes the same few calls, with the same
SDK, every time.

## How the attack happens
1. Token from the client credentials grant (B4-B6).
2. Discovery calls with whatever HTTP client the tool uses (Microsoft
   says ARTEX by default uses "Nmap, curl, wget, Python HTTP clients",
   among others): `GET /v1.0/users`, `/groups`, `/servicePrincipals`,
   `/applications`, `/directoryRoles`, `/roleManagement/directory/roleAssignments`.
3. A call fails (bad `$filter`, wrong property, missing permission);
   the agent reads the error, changes the request and sends it again
   within seconds.
4. What it learns decides the next step (Key Vault, storage, adding a
   credential to another app).

## Real-world use
- Microsoft (2026-11-05), on the agentic secret-abuse case: "The threat
  actor enumerated subscriptions, resource groups, permissions, AI model
  deployments, and service configurations in Azure to map the
  environment." That enumeration was against Azure (ARM) as well;
  Graph enumeration is this rule's slice of it.
- Same post, on fix-and-retry timing: "Approximately 28 seconds after
  the first failed response, a batch rerun began", with further retries
  about 60 and 80 seconds after failures.
- Same post: these tools "may send network traffic with distinctive
  characteristics, such as default user agent strings".

## What it leaves in the logs
`MicrosoftGraphActivityLogs` (needs the Graph activity diagnostic
setting): one row per Graph request with `AppId`, `ServicePrincipalId`,
`UserId` (empty for app-only calls), `RequestMethod`, `RequestUri`,
`ResponseStatusCode`, `UserAgent`, `IPAddress`. The user agent is
attacker-controlled and can be set to the SDK's string.

## Prerequisites
A working app-only token with any Graph application permission (even
`User.Read.All` lets it list users), and the Graph activity log enabled
in the tenant (not on by default; it is a diagnostic setting).

## Mapping
- T1087.004 Account Discovery: Cloud Account (listing users and service
  principals).
- T1069.003 Permission Groups Discovery: Cloud Groups (groups, directory
  roles, role assignments).
- T1526 Cloud Service Discovery (applications and service principals:
  what services exist in the tenant).
All discovery. Not T1580 (Cloud Infrastructure Discovery): that is
compute and storage resources, which Graph does not hold. Checked
against ATT&CK 20.1 (2026-11-07).

## References
- Microsoft, "Threat actors use agentic AI tooling to find and abuse
  exposed secrets", 2026-11-05,
  https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
  (fetched 2026-11-07 through a fetch tool; quotes not checked
  character by character).
- Microsoft Learn, MicrosoftGraphActivityLogs table reference (last
  updated 2026-07-28), fetched 2026-11-07.
- MITRE ATT&CK 20.1 enterprise bundle (fetched 2026-11-07).
