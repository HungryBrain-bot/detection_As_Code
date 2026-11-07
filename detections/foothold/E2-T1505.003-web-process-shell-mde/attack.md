# Server process starting a shell (T1505.003, T1059)

## What the attack is
After an attacker gains code execution through a web application or a
database, the commands they run start as children of the server process.
This repo records only what a defender needs to detect that; it does not
describe how to do it.

## How the attack happens
Not described here beyond this: the attacker's commands run through the
server process, which starts a shell or utility. See ATT&CK T1505.003 for
the technique.

## Real-world use
Microsoft (2026-11-06) reports Storm-3358 exploiting "anonymous file
upload and server-side request forgery (SSRF)" and ARTEX agents "using
utilities like netcat and curl to download these RATs" (WISP, vshell,
AdaptixC2). It does not name the parent process. Recorded lab data pinned
in harness/datasets.yaml (Splunk attack_data, WSUS and CrushFTP
exploitation) shows server processes starting `cmd.exe`; that is not
ARTEX. See docs/threats/artex-phase4-foothold.md.

## What it leaves in the logs
A process creation event with a server process as parent and a shell or
utility as child, with both command lines and the account.
`DeviceProcessEvents`: `InitiatingProcessFileName`,
`InitiatingProcessCommandLine`, `FileName`, `ProcessCommandLine`.

## Prerequisites
Code execution through the application, and a server process allowed to
start other programs.

## Mapping
T1505.003 Web Shell (persistence) and T1059 Command and Scripting
Interpreter (execution). T1190 is how the attacker may have got there and
is not what the rule sees; T1105 fits only the download-utility children
and is not claimed for the rule. Checked against the enterprise bundle
(mitre/cti master, fetched 2026-11-07).

## References
- Microsoft Threat Intelligence, 2026-11-06, https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/ (fetched 2026-11-07)
- MITRE ATT&CK T1505.003, T1059
