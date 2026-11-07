# Logging in to an App Service's publishing endpoints with a non-pipeline identity (T1078.004)

## What the attack is
Each Azure App Service has publishing endpoints (the Kudu/SCM site, FTP,
Web Deploy) that can change the app's files and run commands in its
environment. Anyone who obtains a publishing credential, or an Entra
identity with publish rights on the app, gets that access. For an app that
only a pipeline deploys, such a login is outside normal operations.

## How the attack happens
At the level this repo documents (no procedure is given): the attacker
obtains a credential that can publish to the app, then logs in to one of
the publishing endpoints. Microsoft's Kudu page says browser access with
Entra ID needs a role that includes `Microsoft.Web/sites/publish/Action`.

## Real-world use
No fetched source reports Kudu or App Service publishing abuse by ARTEX or
Storm-3358. The owner's draft lists "Abusing the Azure Kudu API" as a
reported technique; the Microsoft posts of 2026-10-21, 2026-11-05 and
2026-11-06, Wiz, CrowdStrike, Zscaler and Recorded Future do not mention
Kudu or SCM. Microsoft's 2026-11-05 post mentions attempts "to obtain App
Service authentication tokens" and operations returning "App Service
settings", which is related but not the same. See
docs/threats/artex-phase4-foothold.md.

## What it leaves in the logs
`AppServiceAuditLogs`: one row per publishing login with `User`,
`UserDisplayName` (for Entra logins), `UserAddress`, `Protocol`.
Commands run afterwards are not in that table.

## Prerequisites
A publishing credential for the app or an Entra identity with publish
rights; basic authentication enabled if the credential is a shared one.

## Mapping
T1078.004 Cloud Accounts ("Valid accounts in cloud environments"),
tactics initial-access and persistence: the rule sees a valid cloud
identity or app credential used where it is not expected. T1651 Cloud
Administration Command was considered and not used: ATT&CK defines it as
running commands "within virtual machines" through services such as Azure
RunCommand, and App Service is not a virtual machine; the rule also does
not see commands. Checked against the enterprise bundle (mitre/cti master,
fetched 2026-11-07).

## References
- Microsoft Learn, Kudu service overview, https://learn.microsoft.com/en-us/azure/app-service/resources-kudu (fetched 2026-11-07)
- Microsoft Threat Intelligence, 2026-11-05, https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ (fetched 2026-11-07; first 67 percent read verbatim)
- MITRE ATT&CK T1078.004, T1651
