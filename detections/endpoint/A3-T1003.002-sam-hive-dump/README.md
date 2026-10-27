# SAM, SYSTEM or SECURITY hive saved with reg.exe or copied from the config folder

ATT&CK: T1003.002 · Severity: High · Status: test · Tier: baseline · Targets: sentinel, splunk, secops

## Hypothesis
If an attacker dumps the SAM, SYSTEM or SECURITY hive with built-in
tools, a process creation event will show either `reg save` / `reg
export` of the hive root, or a command that names the hive file in
`System32\config`.

## Data sources
- Log source `windows-process-creation` (owner: endpoint team).
- Sentinel: `SecurityEvent` 4688 with command-line auditing (see A1
  for the audit policy and what the schema check cannot see).
- Splunk: `XmlWinEventLog:Security`, `EventCode=4688`.
- SecOps: `WINDOWS_SYSMON` process launch.
- Tier baseline: same source as A1, and a hive dump is high value on
  any Windows estate.

## Detection logic
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine matches regex @'(?i)\breg(\.exe)?"?\s+(save|export)\s+"?(hklm|hkey_local_machine)\\(sam|system|security)"?(\s|$)'
    or CommandLine matches regex @'(?i)system32[\\/]+config[\\/]+(sam|system|security)\b'
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
```
1. Process creation with a command line.
2. Branch one: `reg` or `reg.exe` (optionally quoted path), `save` or
   `export`, then `HKLM\` or `HKEY_LOCAL_MACHINE\` and exactly the hive
   root `SAM`, `SYSTEM` or `SECURITY`, ended by a space, a quote or the
   end of the line. The ending is what separates a hive dump from
   exporting a subkey such as `HKLM\SYSTEM\CurrentControlSet\...`.
3. Branch two: any command line naming `system32\config\sam|system|security`
   with `\` or `/` separators (the recorded esentutl run uses
   `C:\windows/system32/config/SAM`). The word boundary keeps
   `config\systemprofile` (the SYSTEM account's profile folder) out.
4. The rule matches the command line of any process, so a `cmd.exe /c
   reg save ...` wrapper and the `reg.exe` child both fire; that is
   two rows for one action, accepted for a High rule.

The KQL uses single-quoted verbatim strings (`@'...'`) because the
pattern contains a double quote.

## Why this logic
- Alternative 1, any `reg.exe` with `save`: catches every hive saved,
  including software hives used by backup scripts. The hive-root
  anchor keeps it to the three credential hives.
- Alternative 2, Security 4656/4663 object access on the hive files or
  keys: catches API-level dumps without a command line (mimikatz,
  Impacket), but needs SACLs that almost no customer has, and lands in
  high-volume events.
- Alternative 3, image name only (`reg.exe`, `esentutl.exe`): misses
  `cmd /c copy` from a shadow copy and adds noise from benign `reg`
  queries.
- The chosen logic uses the source every Windows customer can turn on
  and covers both public tool paths (registry save, file copy).

## False positives
- Backup or imaging software that saves hives with `reg save` (some
  system-state backup scripts do). Not excluded; allowlist the parent
  per customer if seen.
- Forensic or IR collection scripts run by the customer's own team.
  Not excluded; they should be confirmed by a human anyway.

## Tuning
- The end-of-hive anchor was added after reading the standard-user
  background, which contains `reg export "HKLM\SYSTEM\CurrentControlSet\..."`
  run by a system information script. Without the anchor both recorded
  exports match (Kusto, 2026-10-27).
- `config\systemprofile` was checked with a hand-written negative.
- Production: decide whether `reg export` of the hives should be High
  like `reg save` (it produces text, but still contains the secrets).

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positives | Negatives | Recorded datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 5 of 5 matched | 0 of 5 matched | 2 rows from 45,370 events |
| Splunk Enterprise 10.6.1 | 5 of 5 matched | 0 of 5 matched | 2 rows from 45,370 events |

Positives: 2 recorded (Empire `reg save HKLM\sam`, atomic `esentutl /y
/vss`), 3 hand-written (Volexity's `reg save hklm\security` form, long
quoted hive name, shadow-copy `copy` from Volexity's report).
Negatives: 2 recorded (`reg export` of SYSTEM subkeys), 3 hand-written
(`reg query HKLM\SAM\...`, `reg save` of a software hive,
`config\systemprofile`). The SecOps version was not run.

## Blind spots
- Dumps through the API without a revealing command line: mimikatz
  `lsadump::sam`, Impacket `secretsdump.py` / `reg.py` over remote
  registry (the process runs on the target as `svchost.exe`), custom
  tools calling `RegSaveKeyEx`.
- Renamed `reg.exe` with the hive given in a response file or via
  PowerShell (`[Microsoft.Win32.RegistryKey]` has no save method, but
  a P/Invoke one-liner can call `RegSaveKey`).
- Shadow copies mounted and read by a tool rather than `copy`.
- Hive names written with environment variables or `%SystemRoot%`
  instead of `system32\config`.

## References
- Volexity, Nearest Neighbor Attack (GruesomeLarch), 22 November 2024,
  https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/
  (fetched 2026-10-27).
- MITRE ATT&CK T1003.002, https://attack.mitre.org/techniques/T1003/002/
  (STIX bundle v20.0 read 2026-10-27).
- OTRF Security-Datasets, MIT License,
  https://github.com/OTRF/Security-Datasets at d9d40ef (fetched 2026-10-27).
