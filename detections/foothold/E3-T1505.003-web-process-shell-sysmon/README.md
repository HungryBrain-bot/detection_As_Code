# Web server or database process starts a shell or download tool (Windows Sysmon)

ATT&CK: T1505.003, T1059 · Severity: High · Status: experimental · Tier: targeted · Targets: sentinel

## Hypothesis
Web server and database processes serve requests; they rarely start a
command shell or a download utility. If one does, the server is very
likely running commands for someone, whatever the way in was.

## Data sources
- `windows-process-creation` (endpoint team): `Event` (Sysmon event 1; `ParentImage`, `ParentCommandLine`, `Image`, `CommandLine` from the EventData XML, parsed as in A2).
- Prerequisite: Sysmon installed with process creation (event 1) logged, and its events reaching Sentinel. Hosts with Defender for Endpoint are covered by E2.

## Detection logic
```kql
// see rule.yaml for the full query
```
1. Sysmon event 1; child image ends in `\cmd.exe`, `\powershell.exe`,
   `\pwsh.exe`, `\curl.exe`, `\wget.exe`, `\nc.exe` or `\ncat.exe`.
2. Parent image ends in `\w3wp.exe`, `\nginx.exe`, `\httpd.exe`, a Tomcat
   service wrapper, `\mysqld.exe` or `\mariadbd.exe`; or Java whose command line names an application
   server (catalina, tomcat, jboss, wildfly, jetty, weblogic, websphere,
   glassfish).
3. Drop child command lines listed in `allowed_child_commands` (per
   customer, exact match).

## Why this logic
- Parent and child names, not command-line content: the pair is the
  signal and is independent of the exploit.
- Java only with an app-server marker: Java also runs build tools and
  IDEs that start shells all the time. The recorded Linux dataset pinned
  for E4 has exactly that (a Maven build, java starting `/bin/sh`).
- Exact child names: `cmd.exe` must not match `cmdkey.exe`.
- Parents and children are the owner's list; `apache2` (Debian's name for
  httpd), `mariadbd`, `pwsh`, `dash`, `zsh`, `ncat` and `netcat` were
  added as the same programs under other names.
- Alternative, Defender's own alerts (Microsoft lists "Suspicious shell
  execution from PHP application" and "Possible Web Server compromise
  activity" for this campaign): better tuned where licensed, but not
  queryable in the harness and not under this repo's control.

## False positives
- Applications that call a shell by design (report generators, image
  converters, backup hooks, CGI scripts under httpd). Add their command
  lines to `allowed_child_commands`.
- Administrators restarting services through a web-based admin panel.
- Database maintenance scripts launched by the database server.

## Tuning
- Fill `allowed_child_commands` from two weeks of results before alerting.
- Add other server processes the customer runs (php-fpm, node, gunicorn,
  uwsgi, IIS Express, other Java servers) to the parent patterns.
- No samples have been run.

## Test evidence
Not run on samples. Recorded data pinned for it (not yet run): Splunk attack_data WSUS and CrushFTP Sysmon sets. In them, `w3wp.exe` starting `cmd.exe` is in scope; `wsusservice.exe`, `mmc.exe` and `crushftpservice.exe` starting `cmd.exe` are not, because those parents are not in the list (blind spot). The rule is `experimental`, so it is deployed disabled. See [tests/evidence.md](tests/evidence.md).

## Blind spots
- Linux and Defender-only hosts (E2, E4).
- Server processes not in the list (php-fpm, node, Python app servers,
  vendor services such as WSUS or CrushFTP, both of which appear in the
  recorded data for E3).
- Commands run inside the server process without a child process.
- A renamed shell or utility.
- Java application servers started without a recognised marker (for
  example a Spring Boot `-jar app.jar`).

## References
- Microsoft Threat Intelligence, "ARTEX abuse expands as cybercriminals target financial sector", 2026-11-06, https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/ (fetched 2026-11-07)
- MITRE ATT&CK T1505.003, T1059 (enterprise bundle fetched 2026-11-07)
- docs/threats/artex-phase4-foothold.md; ADR 012
