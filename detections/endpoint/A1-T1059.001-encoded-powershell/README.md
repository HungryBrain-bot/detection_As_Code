# PowerShell started with an encoded command or a download cradle

ATT&CK: T1059.001 · Severity: Medium · Status: test · Tier: baseline · Targets: sentinel, splunk, secops

## Hypothesis
If an attacker runs a payload through PowerShell with `-EncodedCommand`
or a download-and-execute one-liner, the process creation event for
`powershell.exe` / `pwsh.exe` will carry that switch followed by a
Base64 blob, or both a download call and `IEX`, in its command line.

## Data sources
- Log source `windows-process-creation` (owner: endpoint team).
- Sentinel: `SecurityEvent`, event 4688, from the Windows Security
  Events connector. Needs the audit policy "Audit Process Creation" and
  "Include command line in process creation events"; without the
  second, `CommandLine` is empty and the rule never fires (the schema
  check sees the column, so it will not catch this: check that recent
  4688 rows have a non-empty `CommandLine`).
- Splunk: `source="XmlWinEventLog:Security"`, `EventCode=4688`, field
  names as the Windows add-on extracts them from the XML
  (`NewProcessName`, `CommandLine`). `index=wineventlog` is a
  convention; change it per customer.
- SecOps: `WINDOWS_SYSMON` process launch (Sysmon event 1), UDM
  `target.process.file.full_path` and `target.process.command_line`.
- Tier baseline: 4688 in `SecurityEvent` is Microsoft's own connector
  and the most common Windows source in Sentinel; the gate still holds
  the rule back for any customer whose probe or team cannot confirm it.

## Detection logic
Sentinel (the Splunk and SecOps versions use the same regular
expressions):

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith @"\powershell.exe" or NewProcessName endswith @"\pwsh.exe"
| where CommandLine matches regex @"(?i)(^|\s)[-/–—]e(c|n|nc|...|ncodedcommand)?\s+[A-Za-z0-9+/]{20,}"
    or (CommandLine matches regex @"(?i)\b(iex|invoke-expression)\b"
        and CommandLine matches regex @"(?i)(downloadstring|downloadfile|...|start-bitstransfer)")
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
```

1. `EventID == 4688`: process creation only.
2. Image ends in `\powershell.exe` or `\pwsh.exe` (Windows PowerShell
   and PowerShell 7).
3. Encoded branch: a switch that is `-e`, `-ec` or any prefix of
   `-encodedcommand`, introduced by `-`, `/` or an en/em dash, then
   whitespace, then at least 20 Base64 characters. The prefix list is
   spelled out so that `-ExecutionPolicy`, `-ep` and `-Exec` cannot
   match. 20 characters is about 7 UTF-16 characters of script, below
   any useful payload.
4. Cradle branch: the command line contains both an execute call
   (`IEX` / `Invoke-Expression`) and a download call (`Net.WebClient`,
   `DownloadString`, `Invoke-WebRequest` / `iwr`,
   `Invoke-RestMethod` / `irm`, `Start-BitsTransfer`).
5. Output keeps the parent process, which is what a triager needs most.

Differences per SIEM: Splunk filters the image in the base search
(`NewProcessName="*\\powershell.exe"`) so the regex runs on fewer
events, then uses `match()` in `where`. SecOps reads Sysmon, not 4688,
because `WINDOWS_SYSMON` is the log type the catalogue declares for it.

## Why this logic
- Alternatives considered:
  - Match `-enc` / `-e` anywhere (common in public rules): also fires
    on `-ExecutionPolicy`, `-ep`, and non-PowerShell tools with an `-e`
    flag. The recorded background contains `ClipRenew.exe -e`, which a
    bare `-e` match on any process would flag. Requiring the PowerShell
    image and a Base64 blob after the switch removes both.
  - Decode and inspect the Base64: better precision, but KQL, SPL and
    YARA-L cannot all decode UTF-16LE Base64 in a scheduled rule the same
    way, and the attacker controls what the payload looks like.
  - Script block logging (4104): sees the decoded script and catches
    PowerShell hosted in other processes, but is off by default and
    lands in the `Event` table with a different owner. It would be a
    separate rule on `windows-powershell-scriptblock`.
- This rule therefore catches the launch, with the parent process,
  from the source most customers already send, and leaves decoding to
  the analyst.

## False positives
- Management agents and installers that start PowerShell with
  `-EncodedCommand` to avoid quoting problems. This is a common
  expectation for configuration-management and RMM tools, but no vendor
  was checked for this doc and none appears in the 45,370 recorded
  events. Not excluded: it needs a per-customer allowlist on
  `ParentProcessName` after a baseline period.
- Admin one-liners that download and run a script (installers piped to
  `iex`). Not excluded; these are also exactly what an attacker does.

## Tuning
- The pipeline's fixture rule matched `-enc`, `-encodedcommand` or
  `-ec ` anywhere in the command line. This rule replaces that with the
  explicit prefix list plus 20 Base64 characters, after reading the
  standard-user dataset (`ClipRenew.exe -e`, `-enc $x`). Dropping the
  Base64 requirement makes 3 of the 6 negative samples match (checked
  in the Kusto engine on 2026-10-27), so the negatives do guard it.
- `Invoke-WebRequest ... -OutFile` without `IEX` is deliberately not
  matched (negative sample); that download is A4's territory when done
  by a LOLBin, and a separate tuning decision for PowerShell.
- Production still needs: an allowlist of known management parents per
  customer, and a decision on `pwsh.exe` installed outside
  `Program Files`.

## Test evidence
Run on 2026-10-27 in two real engines; details in
[tests/evidence.md](tests/evidence.md), raw output in
`tests/results/kusto.json` and `tests/results/splunk.json`.

| Engine | Positives | Negatives | Recorded datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 6 of 6 matched | 0 of 6 matched | 2 rows from 45,370 events |
| Splunk Enterprise 10.6.1 | 6 of 6 matched | 0 of 6 matched | 2 rows from 45,370 events |

Positives: 2 recorded (OTRF Empire launcher and Empire Run-key stager),
4 hand-written (full `-EncodedCommand` with pwsh, Medusa-style
`-exec bypass -enc`, `-ec`, a download cradle). Negatives: 2 recorded
(`ClipRenew.exe -e`, outer `powershell -c "... -enc $x"`), 4
hand-written. The 2 dataset rows are the two Empire stagers and nothing
else. The SecOps version was not run (no YARA-L engine outside SecOps).

## Blind spots
- PowerShell hosted in another process (`System.Management.Automation`
  loaded by a custom binary, PowerShdll, `msbuild` inline tasks): no
  `powershell.exe` 4688 at all.
- Renamed `powershell.exe`: 4688 has no `OriginalFileName`. The SecOps
  version on Sysmon could add it; the 4688 versions cannot.
- Blob not on the command line: `-enc $x` where `$x` comes from the
  registry or a file is missed at the outer process; it is caught only
  if the inner `powershell -enc <blob>` is logged too.
- Cradles written with obfuscation (string concatenation, backticks,
  `.Invoke()` on a variable as in the Medusa example where the method
  name is hidden) only match while both `iex` and one download keyword
  survive in clear text.
- Command-line auditing turned off or the event dropped by an attacker
  with admin rights (audit policy change, log clearing).

## References
- CISA AA25-071A, Medusa Ransomware, 12 March 2025,
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
  (fetched 2026-10-27).
- MITRE ATT&CK T1059.001, https://attack.mitre.org/techniques/T1059/001/
  (STIX bundle v20.0 read 2026-10-27).
- OTRF Security-Datasets, MIT License,
  https://github.com/OTRF/Security-Datasets at d9d40ef (fetched
  2026-10-27).
