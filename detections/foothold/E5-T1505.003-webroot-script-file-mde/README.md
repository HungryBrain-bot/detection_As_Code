# New server-side script file in a web root (Defender for Endpoint)

ATT&CK: T1505.003 · Severity: Medium · Status: experimental · Tier: targeted · Targets: sentinel

## Hypothesis
Server-side script files in a web root change when a release is deployed,
by the deployment tool. A new or changed script file written by anything
else, and above all by a database process, is likely a web shell.

## Data sources
- `mde-advanced-hunting` (endpoint team): `DeviceFileEvents`, Windows and
  Linux. Column names and types from Microsoft's Azure-Sentinel repo table
  definition (commit c0c2dc2, read directly).
- Prerequisite: Defender for Endpoint on the web servers. Hosts with
  Sysmon instead are covered by E6 (Windows only).
- `ActionType` values `FileCreated`, `FileRenamed` and `FileModified` are
  Defender's usual names; not checked against a live tenant.

## Detection logic
```kql
// E5: server-side script file in a web root (detections/foothold/E5-T1505.003-webroot-script-file-mde/README.md)
let script_ext = @"(?i)\.(jspx?|aspx|ashx|asmx|asp|php[0-9]?|phtml)$";
let web_roots = @"(?i)(\\inetpub\\wwwroot\\|\\wwwroot\\|/var/www/|/usr/share/nginx/html/|/srv/www/|[\\/]webapps[\\/]|[\\/]htdocs[\\/]|\\Web Server Extensions\\[0-9]+\\TEMPLATE\\LAYOUTS\\)";
let database_writers = @"(?i)^(mysqld|mariadbd|sqlservr|postgres)(\.exe)?$";
// Per customer: processes that deploy web content (build agents, Web Deploy, rsync from CI).
let deployment_writers = dynamic(["msdeploy.exe"]);
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName matches regex script_ext and FolderPath matches regex web_roots
| where not(InitiatingProcessFileName in~ (deployment_writers))
| extend WriterIsDatabase = InitiatingProcessFileName matches regex database_writers
| extend AlertSeverity = iff(WriterIsDatabase, "High", "Medium")
| project TimeGenerated, DeviceName, ActionType, FolderPath, FileName, Writer = InitiatingProcessFileName,
          WriterCommandLine = InitiatingProcessCommandLine, WriterAccount = InitiatingProcessAccountName,
          WriterIsDatabase, AlertSeverity
```
1. `ActionType` is created, renamed or modified.
2. File name ends in .jsp, .jspx, .aspx, .ashx, .asmx, .asp, .php
   (optionally with a digit) or .phtml.
3. Folder path is a web root: `\inetpub\wwwroot\`, any `\wwwroot\`,
   `/var/www/`, `/usr/share/nginx/html/`, `/srv/www/`, `webapps`,
   `htdocs`, SharePoint `TEMPLATE\LAYOUTS`.
4. Writer not in `deployment_writers` (default `msdeploy.exe`).
5. `WriterIsDatabase` and `AlertSeverity` High when the writer is mysqld,
   mariadbd, sqlservr or postgres; Medium otherwise.

## Why this logic
- Extension plus location, not file content: Defender's file events do
  not carry content, and location is what makes a script executable by
  the server.
- Database writer raised to High: a database has no reason to write
  script files into a web root. Zscaler (2026-10-14) lists "Presence of
  *.aspx or *.jsp files in unexpected web application paths" as potential
  web shell activity; the database-writer emphasis is the owner's.
- Deployment tools are allowlisted rather than release windows: windows
  differ per customer and an attacker can write during one.
- Alternative, file integrity monitoring with hashes: more precise where
  deployed; not a declared source here.

## False positives
- Deployments by tools not in `deployment_writers` (CI agents, rsync,
  robocopy, git pulls, package managers). Add them per customer.
- Tomcat expanding a deployed WAR into `webapps` (java writes .jsp files).
  Expected after each deployment; add the deployment host or schedule.
- CMS plugins and updaters that write PHP files (WordPress, Drupal).
- Upload features that store files under the web root with a script
  extension: a finding in itself.

## Tuning
- Fill `deployment_writers` from two weeks of results before alerting.
- Narrow `web_roots` to the customer's real web roots.
- No samples have been run.

## Test evidence
Not run. No positive or negative samples exist and the query has not been
executed in the Kusto emulator; no recorded Defender for Endpoint data is
available. The rule is `experimental`, so it is deployed disabled. See
[tests/evidence.md](tests/evidence.md).

## Blind spots
- Web shells with other extensions the server runs (.cfm, .cgi, .py, .pl,
  .war files themselves), or in web roots outside the patterns.
- Changes to existing legitimate scripts by a deployment tool on the
  allowlist.
- Web shells that live only in memory.

## References
- Zscaler ThreatLabz, 2026-10-14, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (fetched 2026-11-07)
- Microsoft Threat Intelligence, 2026-11-06, https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/ (fetched 2026-11-07)
- MITRE ATT&CK T1505.003 (enterprise bundle fetched 2026-11-07)
- `schemas/reference/sentinel/DeviceFileEvents.yaml`
- docs/threats/artex-phase4-foothold.md; ADR 012
