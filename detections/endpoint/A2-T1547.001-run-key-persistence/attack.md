# Registry Run key persistence (T1547.001)

## What the attack is
Windows starts every program listed under the `Run` and `RunOnce`
registry keys when a user logs on (HKCU) or when any user logs on
(HKLM). An attacker who adds a value there gets their payload started
again after every reboot, with no service, scheduled task or exploit
needed. It is one of the oldest and still most used persistence
methods because a standard user can write their own HKCU key.

## How the attack happens
1. The attacker has code running as a user (or as an admin for HKLM).
2. They write a value under one of:
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (no admin),
   `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (admin),
   the `RunOnce` / `RunOnceEx` siblings, the `WOW6432Node` copies, or
   `...\Policies\Explorer\Run`.
3. They write it with whatever is running: `reg.exe add`,
   PowerShell `Set-ItemProperty` / `New-ItemProperty`, WMI, or the
   implant's own registry API calls. Empire's `persistence/userland/registry`
   module, recorded in the OTRF data used here, stores the encoded
   stager in another value and sets `Run\Updater` to
   `powershell -c "$x=$((gp HKCU:...).Debug); powershell -Win Hidden -enc $x"`.
4. The value data points to the payload: a script host command line, a
   `rundll32` call on a dropped DLL, or a binary in a user-writable folder.
5. At next logon Explorer starts it, so the attacker's access survives
   a reboot.

## Real-world use
- Microsoft Incident Response, "The five-day job: A BlackByte
  ransomware intrusion case study" (6 July 2023): in a BlackByte 2.0
  intrusion "the threat actor created the following registry run keys to
  run a payload each time a user signs in", value `MsEdgeMsE` under
  HKCU `...\CurrentVersion\Run`, each starting `rundll32` on a DLL in a
  user folder or `C:\temp`.
- Rapid7, "Ongoing Social Engineering Campaign Linked to Black Basta
  Ransomware Operators" (10 May 2024, updated 17 January 2025): the
  actor's batch script "creates a run key to execute a batch script via
  PowerShell". Rapid7 links the activity to Black Basta but does not
  name the actor itself.
- MITRE ATT&CK v20.0 lists 59 groups, 3 campaigns and 205 software
  entries using T1547.001 (STIX bundle read 2026-10-27).

## What it leaves in the logs
- Sysmon event 13 (RegistryEvent, value set): `Image` (the writing
  process), `TargetObject` (full key and value name; HKCU appears as
  `HKU\<SID>\...`), `Details` (value data), `EventType` `SetValue`.
  Needs a Sysmon config that logs these keys (the widely used public
  configs include them; not checked for this doc).
- Security 4657 only if a SACL is set on the key; rare.
- The process that wrote it (4688 / Sysmon 1), e.g. `reg.exe add ...`.
- What the attacker controls: the writing process (they can inject
  into or copy a binary into a trusted path if they are admin), the
  value name (often mimics a vendor: `Updater`, `MsEdgeMsE`,
  `OneNote Update`), and they can use a different autostart point
  altogether.

## Prerequisites
Code execution as the target user for HKCU, or administrator for HKLM.
Usually follows initial access and an execution technique (T1059.001
PowerShell in the recorded data).

## Mapping
T1547.001 Boot or Logon Autostart Execution: Registry Run Keys /
Startup Folder, tactics persistence and privilege-escalation (both as
ATT&CK lists them for this technique; an HKLM Run value runs for every
user who logs on). The Startup folder half of T1547.001 is a file
write, not a registry write, and is not covered by this rule. Not
T1112 (Modify Registry): that is the generic technique; this rule
looks at specific autostart keys.

## References
- Microsoft Incident Response, "The five-day job: A BlackByte ransomware
  intrusion case study", 6 July 2023,
  https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/
  (fetched 2026-10-27).
- Rapid7, "Ongoing Social Engineering Campaign Linked to Black Basta
  Ransomware Operators", 10 May 2024,
  https://www.rapid7.com/blog/post/2024/05/10/ongoing-social-engineering-campaign-linked-to-black-basta-ransomware-operators
  (fetched 2026-10-27).
- MITRE ATT&CK T1547.001, https://attack.mitre.org/techniques/T1547/001/
  (STIX bundle v20.0 read 2026-10-27).
- OTRF Security-Datasets, empire_persistence_registry_modification_run_keys_*,
  commit d9d40ef, https://github.com/OTRF/Security-Datasets (fetched 2026-10-27).
