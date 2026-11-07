# Script file placed in a web root (T1505.003)

## What the attack is
A web shell is a server-side script the web server will run on request,
giving the attacker repeat access to the server. This repo records only
what a defender needs to detect a new one; it does not describe how one is
placed.

## How the attack happens
Not described here beyond this: a script file appears in a location the
web server serves, written by something other than the normal deployment.
See ATT&CK T1505.003 for the technique.

## Real-world use
Microsoft (2026-11-06) says ARTEX campaigns "use web shells for
persistence on compromised web servers", without a file type or a way of
writing them. Zscaler (2026-10-14) lists "*.aspx or *.jsp files in
unexpected web application paths" as an indicator for the Korean
financial intrusions. The owner's draft says a JSP web shell was written
through MySQL's general log; no fetched source supports that (see
docs/threats/artex-phase4-foothold.md). Recorded lab data pinned for E6
(Splunk attack_data, SharePoint and MOVEit) shows .aspx files written into
web roots; that is not ARTEX.

## What it leaves in the logs
A file creation or modification event with the path, file name and the
writing process. `DeviceFileEvents`: `ActionType`, `FolderPath`,
`FileName`, `InitiatingProcessFileName`.

## Prerequisites
A way to write a file the web server serves.

## Mapping
T1505.003 Web Shell, tactic persistence. Checked against the enterprise
bundle (mitre/cti master, fetched 2026-11-07).

## References
- Microsoft Threat Intelligence, 2026-11-06, https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/ (fetched 2026-11-07)
- Zscaler ThreatLabz, 2026-10-14, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (fetched 2026-11-07)
- MITRE ATT&CK T1505.003
