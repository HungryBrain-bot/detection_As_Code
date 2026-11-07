# Web server or database process starts a shell or download tool (Defender for Endpoint)

ATT&CK: T1505.003, T1059 · Severity: High · Status: experimental · Tier: targeted · Targets: sentinel

## Hypothesis
Web server and database processes serve requests; they rarely start a
command shell or a download utility. If one does, the server is very
likely running commands for someone, whatever the way in was.

## Data sources
- `mde-advanced-hunting` (endpoint team): `DeviceProcessEvents`, Windows
  and Linux. Column names and types from Microsoft's Azure-Sentinel repo
  table definition (commit c0c2dc2, read directly).
- Prerequisite: Defender for Endpoint on the servers, streamed to Sentinel
  by the Defender XDR connector. Hosts with Sysmon instead are covered by
  E3 (Windows) and E4 (Linux).

## Detection logic
```kql
// see rule.yaml for the full query
```
1. Child is a shell or download utility: cmd, PowerShell/pwsh, sh, bash,
   dash, zsh, curl, wget, nc/ncat/netcat (exact file names).
2. Parent is w3wp, nginx, httpd/apache2, a Tomcat service wrapper,
   mysqld or mariadbd; or Java whose command line names an application
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
Not run. No positive or negative samples exist and the query has not been
executed in the Kusto emulator; no recorded Defender for Endpoint data is
available. The rule is `experimental`, so it is deployed disabled. See
[tests/evidence.md](tests/evidence.md).

## Blind spots
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
- `schemas/reference/sentinel/DeviceProcessEvents.yaml`
- docs/threats/artex-phase4-foothold.md; ADR 012
