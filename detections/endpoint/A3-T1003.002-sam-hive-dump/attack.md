# SAM / SYSTEM hive dump (T1003.002)

## What the attack is
The SAM registry hive holds the NTLM hashes of every local account;
the SYSTEM hive holds the boot key that decrypts them; SECURITY holds
LSA secrets and cached domain logons. With copies of these files an
attacker can crack or pass the hashes offline, which often includes a
local administrator password shared across many machines.

## How the attack happens
1. The attacker needs administrator or SYSTEM on the host; the hive
   files are locked and readable only by SYSTEM while Windows runs.
2. Option A, the registry API through `reg.exe`:
   `reg save HKLM\SAM C:\ProgramData\sam.save`, the same for `SYSTEM`
   and `SECURITY`. `reg export` works too but writes text.
3. Option B, copy the files from `C:\Windows\System32\config\` through
   something that bypasses the lock: a volume shadow copy
   (`vssadmin create shadow`, then
   `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM`),
   or `esentutl.exe /y /vss C:\Windows\System32\config\SAM /d out`,
   which is what the recorded OTRF atomic does.
4. They stage the copies (often zip them) and exfiltrate, then run
   `secretsdump.py` or `mimikatz lsadump::sam` offline.
5. The recovered hashes are used for lateral movement (pass-the-hash,
   T1550.002) or cracked.

## Real-world use
- Volexity, "The Nearest Neighbor Attack: How A Russian APT Weaponized
  Nearby Wi-Fi Networks for Covert Access" (22 November 2024): the actor
  Volexity tracks as GruesomeLarch (MITRE maps the campaign to APT28)
  ran `reg save hklm\sam C:\ProgramData\sam.save`, and the same for
  `security` and `system`, from a batch file, then zipped them into
  `out.zip`. It also copied `config\SYSTEM` out of a volume shadow copy.
- MITRE ATT&CK v20.0 lists 14 groups and 8 campaigns using T1003.002
  (STIX bundle read 2026-10-27); several procedures name `reg save`
  (APT29, APT41, FIN13, Ember Bear, Operation CuckooBees). Those are
  MITRE's summaries, not reports fetched for this doc.

## What it leaves in the logs
- Security 4688 / Sysmon 1: `reg.exe` with `save` / `export` and the
  hive name; `esentutl.exe`, `cmd.exe /c copy` or `xcopy` with a path
  into `System32\config`.
- Sysmon 11 (file create) for the output file, Security 4656/4663 if
  the hive files or keys are audited (rarely configured).
- What the attacker controls: they can rename `reg.exe`, call
  `RegSaveKeyEx` from their own tool (mimikatz, Impacket's
  `reg.py save` over remote registry, custom loaders), or read the
  shadow copy from code without any revealing command line.

## Prerequisites
Local administrator or SYSTEM (T1078 valid accounts or a privilege
escalation), usually after initial access and discovery.

## Mapping
T1003.002 OS Credential Dumping: Security Account Manager, tactic
credential-access. Saving `SECURITY` alone is closer to T1003.004 (LSA
Secrets) and T1003.005 (Cached Domain Credentials); the rule maps only
T1003.002 because SAM and SYSTEM are almost always taken together with
it. The shadow-copy step itself (vssadmin) is T1006 / T1490 territory
and is not what this rule detects.

## References
- Volexity, "The Nearest Neighbor Attack: How A Russian APT Weaponized
  Nearby Wi-Fi Networks for Covert Access", 22 November 2024,
  https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/
  (fetched 2026-10-27).
- MITRE ATT&CK T1003.002, https://attack.mitre.org/techniques/T1003/002/;
  campaign C0051 (APT28 Nearest Neighbor), STIX bundle v20.0 read 2026-10-27.
- OTRF Security-Datasets, empire_shell_reg_dump_sam and
  cmd_sam_copy_esentutl, commit d9d40ef,
  https://github.com/OTRF/Security-Datasets (fetched 2026-10-27).
