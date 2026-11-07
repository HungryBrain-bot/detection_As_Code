# ARTEX-style agentic attacks, Phase 4: initial exploitation and foothold

Written 2026-11-07 for the owner's blog series. Phase 4 is how an agent
turns low-severity web bugs into access to a server. Earlier phases:
[Phase 1](artex-phase1-credential-sourcing.md) (credential sourcing),
[Phase 2](artex-phase2-recon.md) (recon); Phase 3 (identity) is in its own
file. This file maps each detection the draft suggests to what was built,
records which of the draft's factual claims the sources support, and keeps
the hardening guidance. It does not describe how to carry out any of the
techniques.

## What was built

| Blog draft says | Built | Type |
|---|---|---|
| One session or client reading many record IDs within minutes; IDs that rise steadily, or many 403/404 mixed with 200; data volume far above the per-user baseline | [E1](../../detections/foothold/E1-T1190-sequential-record-access/) (App Service only; record ID patterns per app) | Rule, T1190 |
| A web server or database process (`w3wp.exe`, `java`, `tomcat`, `nginx`, `httpd`, `mysqld`) starting `cmd`, `powershell`, `sh`, `bash`, `curl`, `wget`, `nc` | [E2](../../detections/foothold/E2-T1505.003-web-process-shell-mde/) (Defender for Endpoint, Windows and Linux), [E3](../../detections/foothold/E3-T1505.003-web-process-shell-sysmon/) (Windows Sysmon), [E4](../../detections/foothold/E4-T1505.003-web-process-shell-linux-sysmon/) (Sysmon for Linux via Syslog) | Rules, T1505.003 + T1059 |
| New `.jsp`, `.aspx` or `.php` files in web roots, especially written by the database process | [E5](../../detections/foothold/E5-T1505.003-webroot-script-file-mde/) (Defender for Endpoint), [E6](../../detections/foothold/E6-T1505.003-webroot-script-file-sysmon/) (Windows Sysmon); database writer raises the alert to High | Rules, T1505.003 |
| Changes to MySQL `general_log` settings in database audit logs | **Not built** | Dropped in this pass (owner's decision, 2026-11-07, project thread). Parked in BUILD_LOG.md |
| Kudu/SCM command execution on App Services normally deployed only through a pipeline | [E8](../../detections/foothold/E8-T1078.004-app-service-publishing-login/) detects the **publishing login** by a non-pipeline identity (`AppServiceAuditLogs`), not command execution: no Microsoft page read documents a log of Kudu commands | Rule, T1078.004 |
| Outbound connections from servers to `webhook.site` and similar request-capture services | [E9](../../detections/foothold/E9-T1567.004-request-capture-egress/) (Defender for Endpoint; domain list is a parameter) | Rule, T1567.004 |
| Hardening: re-rate IDOR, upload and SSRF findings; inventory peripheral apps; restrict egress; IMDSv2 | Guidance below | Not rules |

State of the rules: all eight are `status: experimental` (deployed
disabled), `targeted`, Sentinel only. No hand-written positive or negative
samples exist; the owner asked for the rules and docs first. Every query
was run once in the Kusto emulator on empty tables (it parses and runs).
Three were run on recorded Splunk attack_data Sysmon sets (lab
exploitation, not ARTEX): E3 1 row of 9 events (`w3wp.exe` starting
`cmd.exe`), E4 0 of 42 (a Maven build's java starting `sh`, excluded as
intended), E6 7 of 7 (SharePoint and MOVEit web shell files). E1, E2, E5,
E8 and E9 have never matched anything. All thresholds in E1 are this
project's. Design decisions are in ADR 012.

Why the ATT&CK IDs (enterprise bundle, mitre/cti master, fetched
2026-11-07; none revoked or deprecated): T1190 for E1 (the IDOR is the
exploited "software bug"; T1213 / T1213.006 not used, the data is read
through the app's API); T1505.003 for the server-process and web-root
rules, with T1059 (T1059.004 on Linux) for the shell; T1078.004 for E8
(T1651 not used: ATT&CK limits it to commands "within virtual machines",
and E8 does not see commands); T1567.004 for E9 (its description names
`webhook.site`). T1105 fits only the download-utility children of E2-E4
and is not claimed. T1552.005 (Cloud Instance Metadata API) belongs to
the IMDS hardening item; no rule was built for it.

## Claims in the draft, checked against sources (2026-11-07)

Sources fetched: Microsoft's 2026-11-06 Storm-3358 post (read in full),
Microsoft's 2026-10-21 Storm-0940 post (read in full in two parts),
Microsoft's 2026-11-05 post (first 67 percent verbatim; the rest only as a
summary, not relied on), Wiz (2026-10-22), CrowdStrike (2026-10-07),
Zscaler (2026-10-14), Recorded Future (2026-10-16), and Microsoft Learn
pages for App Service and Kudu. All came through a fetch tool, so quotes
were not checked character by character.

| Claim in the draft | Status | Source and what it says |
|---|---|---|
| Microsoft's post exists at the cited URL, dated 2026-11-06 | **Supported** | Resolves; title "ARTEX abuse expands as cybercriminals target financial sector", by Microsoft Threat Intelligence, page date November 6 (metadata published 2026-11-07T02:44 UTC) |
| Storm-3358's chain: anonymous file upload, then SSRF, then download a tool with netcat or curl, then install remote-access tools | **Supported in substance; order and attribution need care** | Storm-3358 is "a Cambodia-based intrusion cluster that primarily targets financial organizations in Southeast Asia". It and similar actors "exploit security flaws including anonymous file upload and server-side request forgery (SSRF)" and "install open-source remote access trojans (RATs)"; "Storm-3358 has used the WISP, vshell, and AdaptixC2 RATs"; "Microsoft has observed ARTEX agents using utilities like netcat and curl to download these RATs". Microsoft lists upload and SSRF together, not as steps of one chain, and attributes the netcat/curl observation to "ARTEX agents". Suggested wording: "Microsoft reports Storm-3358 exploiting anonymous file upload and SSRF flaws, and ARTEX agents using netcat and curl to download the WISP, vshell and AdaptixC2 RATs." |
| Other reported techniques in the same phase: writing a JSP web shell through MySQL's `general_log` | **Not supported** | None of the fetched sources mentions MySQL, `general_log` or JSP. Microsoft says ARTEX campaigns "use web shells for persistence on compromised web servers", with no file type or method. Zscaler lists "*.aspx or *.jsp files in unexpected web application paths" as a web shell indicator. Suggested wording: "Microsoft reports web shells used for persistence on compromised web servers." Remove the MySQL detail unless the owner has another source |
| Other reported techniques: abusing the Azure Kudu API | **Not supported** | No fetched source mentions Kudu or SCM. Microsoft's 2026-11-05 post mentions attempts "to obtain App Service authentication tokens" and operations returning "App Service settings" (verbatim part). Suggested wording: drop "Kudu", or say "attempts to obtain App Service tokens and settings (Microsoft, 2026-11-05)" |
| Agents make IDOR worth exploiting; an agent tries every parameter and keeps going | **Inference; one supporting line** | Wiz: the playbook tries to "manipulate predictable identifiers to probe for broken access controls and unauthorized cross-tenant data access". No source reports IDOR exploitation by ARTEX or Storm-3358. Zscaler reports "SQL injection and authentication bypass" in Korean financial portals, not IDOR (Phase 2 noted the same) |
| The pattern is retrying until it works; the agent changes one thing and tries again, often dozens of times | **Partly** | Microsoft (2026-11-06): agentic frameworks "retry variations on the same technique or move on to next-stage actions at machine speed". "Dozens of times" is not in the source |
| Detect sequential access: many record IDs per session, rising IDs or many 403/404, volume above baseline | **Recommended by two sources, not measured** | Zscaler: "alert on sequential lookups and unusually high numbers of records accessed per session". Recorded Future: "repeated requests for different customers' records". Neither gives numbers; E1's thresholds are this project's |
| Web servers don't normally start shells; the process chain is "the most reliable detection in the series" | **Reasonable, not measured** | Microsoft's detections for the campaign include "Suspicious shell execution from PHP application", "Possible Web Server compromise activity" and "Suspicious curl behavior". "Most reliable" is the owner's judgement: no source compares detections, and this repo has no false-positive data for E2-E4 |
| Treat any web server or database process starting a shell as a confirmed incident | **Overstated** | Some applications start shells by design (report generators, converters, CGI). Suggested wording: "treat it as an incident until the parent application is shown to do this by design" |
| No production server has a legitimate reason to contact webhook.site and similar services | **Reasonable, not sourced** | ATT&CK T1567.004 names `webhook.site` among services adversaries use. Integration testing can use these services; on production servers it is rare. Microsoft's post does not mention request-capture services |
| Require IMDSv2 or the equivalent on cloud metadata endpoints | **Sound guidance, not in the Microsoft post** | The Microsoft post does not mention IMDS. It is standard SSRF hardening (ATT&CK T1552.005 covers credential theft from the metadata API) |

## Hardening guidance (from the draft, not rules)

1. **Re-rate low-severity web findings.** IDOR, unauthenticated upload and
   SSRF findings: rate them assuming automated, patient exploitation. "Needs
   a lot of effort to exploit" no longer lowers the risk.
2. **Inventory peripheral apps.** Partner portals, broker tools, mobile
   back-ends and contractor-built apps get the same authentication and
   per-record authorisation checks as core systems. Zscaler and Recorded
   Future both recommend checking that users "can access only the records
   they are authorized to see".
3. **Restrict egress from web servers.** Allow only the destinations the
   app needs. This limits SSRF, tool downloads (the netcat and curl step
   Microsoft reports) and callbacks to request-capture services (E9).
4. **Metadata endpoints.** Require IMDSv2 on AWS (session tokens) and the
   equivalent protections elsewhere, so an SSRF cannot read instance
   credentials.
5. **App Service publishing.** Disable basic authentication for SCM and FTP
   where the pipeline does not need it (Microsoft Learn, "Disable Basic
   Authentication for Deployment"), and send `AppServiceAuditLogs` to the
   SIEM (E8).
6. **Database servers.** Keep database processes from writing into web
   roots (separate hosts or file-system permissions), and give application
   database accounts no rights to change global server settings.

## Sources

- Microsoft Threat Intelligence, "ARTEX abuse expands as cybercriminals target financial sector", 2026-11-06, https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/ (fetched 2026-11-07)
- Microsoft, "AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise", 2026-10-21, https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/ (fetched 2026-11-07)
- Microsoft Threat Intelligence, "Threat actors use agentic AI tooling to find and abuse exposed secrets", 2026-11-05, https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ (fetched 2026-11-07, partial)
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- CrowdStrike, 2026-10-07, https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/ (fetched 2026-11-07)
- Zscaler ThreatLabz, 2026-10-14, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (fetched 2026-11-07)
- Recorded Future, 2026-10-16, https://www.recordedfuture.com/blog/tag-217-artex-south-korean-banks (fetched 2026-11-07)
- Microsoft Learn: AppServiceAuditLogs, App Service monitoring reference, Kudu, Disable Basic Authentication for Deployment (fetched 2026-11-07)
