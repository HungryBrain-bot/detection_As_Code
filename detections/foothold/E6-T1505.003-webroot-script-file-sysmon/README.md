# New server-side script file in a web root (Windows Sysmon)

ATT&CK: T1505.003 · Severity: Medium · Status: experimental · Tier: targeted · Targets: sentinel

## Hypothesis
Server-side script files in a web root change when a release is deployed,
by the deployment tool. A new or changed script file written by anything
else, and above all by a database process, is likely a web shell.

## Data sources
- `windows-file-creation` (endpoint team): `Event` (Sysmon event 11; `Image`, `TargetFilename` from the EventData XML, parsed as in A2).
- Prerequisite: Sysmon with file creation (event 11) logged for the web roots. Many Sysmon configurations filter event 11 to a few paths; the web roots must be included. Linux and Defender hosts are covered by E5.

## Detection logic
```kql
// E6: server-side script file in a web root, Sysmon (detections/foothold/E6-T1505.003-webroot-script-file-sysmon/README.md)
let script_ext = @"(?i)\.(jspx?|aspx|ashx|asmx|asp|php[0-9]?|phtml)$";
let web_roots = @"(?i)(\\inetpub\\wwwroot\\|\\wwwroot\\|[\\/]webapps[\\/]|[\\/]htdocs[\\/]|\\Web Server Extensions\\[0-9]+\\TEMPLATE\\LAYOUTS\\)";
let database_writers = @"(?i)\\(mysqld|mariadbd|sqlservr|postgres)\.exe$";
let deployment_writers = @"(?i)\\msdeploy\.exe$";
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 11
| extend Data = parse_xml(EventData).DataItem.EventData.Data
| mv-apply d = Data on (summarize Fields = make_bag(bag_pack(tostring(d["@Name"]), tostring(d["#text"]))))
| extend Image = tostring(Fields.Image), TargetFilename = tostring(Fields.TargetFilename), User = tostring(Fields.User)
| where TargetFilename matches regex script_ext and TargetFilename matches regex web_roots
| where not(Image matches regex deployment_writers)
| extend WriterIsDatabase = Image matches regex database_writers
| extend AlertSeverity = iff(WriterIsDatabase, "High", "Medium")
| project TimeGenerated, Computer, TargetFilename, Image, User, WriterIsDatabase, AlertSeverity
```
1. Sysmon event 11 (file created; renames and modifications are not in event 11).
2. File name ends in .jsp, .jspx, .aspx, .ashx, .asmx, .asp, .php
   (optionally with a digit) or .phtml.
3. Folder path is a web root: `\inetpub\wwwroot\`, any `\wwwroot\`,
   `webapps`,
   `htdocs`, SharePoint `TEMPLATE\LAYOUTS`.
4. Writer not in `deployment_writers` (default `\msdeploy.exe`, a regex here).
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
Run on recorded data on 2026-11-07 in the Kusto emulator: 7 recorded Sysmon file-creation events (Splunk attack_data, SharePoint and MOVEit web shell files in a lab), 7 rows. Both sets contain only attack events, so this says nothing about false positives. No hand-written samples. The rule is `experimental`, so it is deployed disabled. Details: [tests/evidence.md](tests/evidence.md).

## Blind spots
- Web shells with other extensions the server runs (.cfm, .cgi, .py, .pl,
  .war files themselves), or in web roots outside the patterns.
- Changes to existing legitimate scripts by a deployment tool on the
  allowlist.
- Web shells that live only in memory.
- Modifications of existing files and renames (not in Sysmon event 11).

## References
- Zscaler ThreatLabz, 2026-10-14, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (fetched 2026-11-07)
- Microsoft Threat Intelligence, 2026-11-06, https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/ (fetched 2026-11-07)
- MITRE ATT&CK T1505.003 (enterprise bundle fetched 2026-11-07)
- Splunk attack_data at commit b52ee68 (Apache-2.0): T1505.003/sharepoint_webshell/sysmon_spinstall0.log, T1505.003/moveit_windows-sysmon.log
- docs/threats/artex-phase4-foothold.md; ADR 012
