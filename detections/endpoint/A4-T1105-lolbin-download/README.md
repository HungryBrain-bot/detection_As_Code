# certutil, bitsadmin or curl used to download a file from a URL

ATT&CK: T1105 · Severity: Medium · Status: test · Tier: baseline · Targets: sentinel, splunk, secops

## Hypothesis
If an attacker uses a built-in Windows binary to pull a tool onto a
host, a process creation event will show `certutil.exe`,
`bitsadmin.exe` or `curl.exe` with a URL and that binary's download
switch.

## Data sources
- Log source `windows-process-creation` (owner: endpoint team).
- Sentinel: `SecurityEvent` 4688 with command-line auditing.
- Splunk: `XmlWinEventLog:Security`, `EventCode=4688`.
- SecOps: `WINDOWS_SYSMON` process launch.
- Tier baseline: same source as A1.

## Detection logic
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine matches regex @"(?i)(https?|ftp)://"
| where (NewProcessName endswith @"\certutil.exe" and CommandLine matches regex @"(?i)urlcache|verifyctl")
    or (NewProcessName endswith @"\bitsadmin.exe" and CommandLine matches regex @"(?i)[-/](transfer|addfile)\b")
    or (NewProcessName endswith @"\curl.exe" and CommandLine matches regex @"\s(-[A-Za-z]*[oO]|--output|--remote-name)(\s|=|$)")
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
```
1. Process creation with a URL (`http`, `https` or `ftp`) in the
   command line; this is the cheapest filter, so it runs first.
2. certutil: `urlcache` or `verifyctl` anywhere, with or without a
   leading dash, because the Medusa example in CISA AA25-071A writes
   `certutil -f urlcache`.
3. bitsadmin: `/transfer` or `/addfile` (also with `-`).
4. curl: an output option, short (`-o`, `-O`, or combined like `-sLO`)
   or long (`--output`, `--remote-name`). Without one, curl prints to
   the console and nothing lands on disk.
5. The image is matched with `endswith`, case-insensitive in KQL;
   Splunk lower-cases before `like()`.

## Why this logic
- Alternative 1, any of the three binaries with a URL: curl is used by
  developers and scripts for API calls and health checks; requiring an
  output option keeps it to file downloads.
- Alternative 2, network events (Sysmon 3) from these binaries: misses
  BITS (the download is made by the BITS service), and needs Sysmon.
- Alternative 3, any process with a URL and an output file: covers more
  tools but becomes a generic "something downloaded" rule with a high
  baseline; LOLBin abuse is the specific, high-signal case.

## False positives
- Admin and developer `curl -o` downloads of installers or packages.
  Not excluded; expect some per customer, allowlist by parent or user
  after a baseline.
- Software that uses `bitsadmin /transfer` in install scripts (older
  installers; bitsadmin is deprecated in favour of PowerShell's BITS
  cmdlets). Not excluded.
- `certutil -verifyctl` against Microsoft URLs by certificate tooling.
  Not excluded; an allowlist of Microsoft update domains is a reasonable
  first tuning step.

## Tuning
- The certutil branch does not require a dash before `urlcache`, after
  reading the CISA Medusa example; tested with a hand-written positive
  in that exact form.
- Recorded background includes `certutil -v -enterprise -store` (a
  system information script) and the BITS service's own process; both
  are negatives and not matched.
- Production needs per-customer allowlists for curl and, if certutil
  `verifyctl` is used legitimately, for Microsoft certificate URLs.

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positives | Negatives | Recorded datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 7 of 7 matched | 0 of 10 matched | 1 row from 45,370 events |
| Splunk Enterprise 10.6.1 | 7 of 7 matched | 0 of 10 matched | 1 row from 45,370 events |

Positives: 1 recorded (atomic `bitsadmin /transfer`), 6 hand-written
(three certutil forms including the CISA Medusa one, `bitsadmin
/addfile`, two curl forms). Negatives: 6 recorded (certutil `-store`,
BITS service), 4 hand-written. There is no recorded certutil or curl
download in these datasets, so those branches rest on hand-written
samples. The SecOps version was not run.

## Blind spots
- Renamed or copied binaries: 4688 has no `OriginalFileName`.
- Other download paths: PowerShell (`Invoke-WebRequest`,
  `Start-BitsTransfer`, covered partly by A1's cradle branch), `mshta`,
  `msiexec /i http://`, `wget` from WSL, `finger`, WebDAV / UNC copies.
- BITS jobs created through the COM API or PowerShell, with no
  `bitsadmin.exe` process.
- URLs passed in a file (`curl -K config.txt`) or built from variables
  in a script.

## References
- CISA AA25-071A, Medusa Ransomware, 12 March 2025,
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
  (fetched 2026-10-27).
- Microsoft Threat Intelligence, Storm-1811 and Quick Assist, 15 May 2024,
  https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
  (fetched 2026-10-27).
- MITRE ATT&CK T1105, https://attack.mitre.org/techniques/T1105/
  (STIX bundle v20.0 read 2026-10-27).
- OTRF Security-Datasets, MIT License,
  https://github.com/OTRF/Security-Datasets at d9d40ef (fetched 2026-10-27).
