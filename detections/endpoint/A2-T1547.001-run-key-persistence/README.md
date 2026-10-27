# Registry Run key value set by a process outside installer and Program Files paths

ATT&CK: T1547.001 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel, splunk, secops

## Hypothesis
If an attacker adds a Run-key value for persistence, Sysmon logs a
registry value set (event 13) on a Run / RunOnce key, and the process
that wrote it is a script host, a LOLBin or a binary in a user-writable
folder, not an installer or software installed under Program Files.

## Data sources
- Log source `windows-registry-set` (owner: endpoint team): Sysmon
  event 13 with a config that includes the Run keys.
- Sentinel: the `Event` table, `Source == "Microsoft-Windows-Sysmon"`.
  Sysmon fields are inside the `EventData` XML, read with `parse_xml`
  the same way Microsoft's Sysmon parser in the Azure-Sentinel repo
  does. The schema check can confirm the `Event` table and its columns;
  it cannot see inside `EventData`, so it will not notice a Sysmon
  config that drops event 13.
- Splunk: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`,
  `EventCode=13`.
- SecOps: `WINDOWS_SYSMON`, UDM `REGISTRY_MODIFICATION`.
- Tier targeted: Sysmon is not a default source, so the rule goes only
  to customers who include it.

## Detection logic
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 13
| extend Data = parse_xml(EventData).DataItem.EventData.Data
| mv-apply d = Data on (summarize Fields = make_bag(bag_pack(tostring(d["@Name"]), tostring(d["#text"]))))
| extend EventType = tostring(Fields.EventType), Image = tostring(Fields.Image),
    TargetObject = tostring(Fields.TargetObject), Details = tostring(Fields.Details)
| where EventType == "SetValue"
| where TargetObject matches regex @"(?i)\\Software\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Policies\\Explorer\\Run)\\"
| where not(Image matches regex @"(?i)^C:\\Windows\\(System32|SysWOW64)\\msiexec\.exe$")
| where not(Image matches regex @"(?i)^C:\\Program Files( \(x86\))?\\")
| where not(Image matches regex @"(?i)^C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\")
| project TimeGenerated, Computer, UserName, Image, TargetObject, Details
```
1. Sysmon event 13 only, value set (not key create or delete).
2. Unpack the `EventData` XML into named fields.
3. The key path must be one of the autostart keys, in any hive (HKLM,
   `HKU\<SID>`), including the 32-bit `WOW6432Node` view. The trailing
   `\` means a value under the key, so `RunMRU` (Run-dialog history)
   does not match.
4. Drop writes by `msiexec.exe` (installers), by anything under
   `Program Files` (installed software and its updaters), and by the
   Defender platform folder. All three are full-path matches, so a
   copy of `msiexec.exe` in `%TEMP%` is still reported.

Splunk and SecOps apply the same filters. SecOps matches the key with
`(\\|$)` at the end because Google's Sysmon parser may store the value
name separately from `registry_key` [not verified].

## Why this logic
- Alternative 1, every Run-key write: simplest and catches everything,
  but software installs and updates write Run keys constantly; the
  recorded background already has Defender writing one.
- Alternative 2, allowlist value names or data: names are attacker
  chosen (`Updater`, `MsEdgeMsE` look benign) and data changes per
  version, so the allowlist never ends.
- Alternative 3, flag only suspicious value data (script hosts,
  `rundll32`, user folders): good precision, but misses a dropped EXE
  with a plausible name. It is a useful second rule, not this one.
- Chosen: exclude by who wrote it, using the full image path. Writing
  under `Program Files` needs admin, so a standard-user attacker (the
  common case, HKCU) cannot hide behind it.

## False positives
- Per-user applications that install under `%LOCALAPPDATA%` (common
  for chat, meeting and browser updaters) and set an HKCU Run value at
  install or update. Not excluded; they need a per-customer allowlist
  of image paths after a baseline. None appear in the recorded data.
- Group Policy or management scripts (PowerShell run by an agent) that
  set Run values. Not excluded; allowlist the parent agent per customer.

## Tuning
- Program Files and Defender exclusions were added after reading the
  recorded standard-user dataset, where `MsMpEng.exe` writes
  `HKLM\...\Run\WindowsDefender`. Removing the Program Files exclusion
  makes 2 of the 4 negative samples match (Kusto, 2026-10-27).
- Production needs a baseline of `%LOCALAPPDATA%` updaters per customer
  and a decision on whether `RunOnce` writes by Windows setup
  components should be allowlisted.

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positives | Negatives | Recorded datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 4 of 4 matched | 0 of 4 matched | 2 rows from 45,370 events |
| Splunk Enterprise 10.6.1 | 4 of 4 matched | 0 of 4 matched | 2 rows from 45,370 events |

Positives: 2 recorded (Empire `Run\Updater` as standard user and as
elevated user), 2 hand-written (RunOnce from `%TEMP%`, WOW6432Node Run
by `reg.exe`). Negatives: 1 recorded (Defender), 3 hand-written
(`msiexec.exe`, a Program Files updater, `RunMRU`). The SecOps version
was not run.

## Blind spots
- An admin attacker who writes from a binary placed under
  `Program Files`, or who injects into an installer.
- Other autostart points: Startup folder, `Winlogon\Userinit` and
  `Shell`, `Explorer\Shell Folders`, `Active Setup`, services, scheduled
  tasks.
- Writes made offline (editing the hive file while Windows is not
  running), which no Sysmon event can see.
- Sysmon not installed, config missing the keys, or Sysmon stopped by
  an admin attacker.

## References
- Microsoft Incident Response, BlackByte 2.0 case study, 6 July 2023,
  https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/
  (fetched 2026-10-27).
- Azure-Sentinel, `Parsers/Sysmon/Sysmon-AllVersions_Parser.txt` (how
  Sysmon lands in `Event`), https://github.com/Azure/Azure-Sentinel at
  c34840b (fetched 2026-10-27).
- Microsoft Learn, Event table reference,
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event
  (fetched 2026-10-27).
- OTRF Security-Datasets, MIT License,
  https://github.com/OTRF/Security-Datasets at d9d40ef (fetched 2026-10-27).
