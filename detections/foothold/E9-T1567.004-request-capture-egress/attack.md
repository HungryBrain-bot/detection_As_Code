# Calling out to a request-capture service (T1567.004)

## What the attack is
Request-capture services (webhook.site, ProjectDiscovery's interactsh
servers and similar) record any HTTP or DNS request sent to a URL or name
they hand out. Attackers use them to confirm that a server can be made to
call out (server-side request forgery, blind command execution) and to
send small amounts of data out over an ordinary-looking HTTPS request.

## How the attack happens
At the level this repo documents (no procedure is given): the attacker
obtains a capture URL, causes the target server to request it, and reads
the captured request on the service's page.

## Real-world use
- No fetched ARTEX source names webhook.site or interactsh. Microsoft
  (2026-11-06) reports Storm-3358 exploiting "server-side request forgery
  (SSRF)" without saying how it was confirmed.
- MITRE ATT&CK T1567.004 names `webhook.site` among services adversaries
  use for webhook exfiltration.
- Recorded lab data (Splunk attack_data, WSUS exploitation, pinned in
  harness/datasets.yaml) shows `curl.exe` sending command output to a
  `webhook.site` URL. That is not ARTEX.
See docs/threats/artex-phase4-foothold.md.

## What it leaves in the logs
An outbound connection from the server to the service's host:
`DeviceNetworkEvents` `RemoteUrl`, `RemoteIP`, `InitiatingProcessFileName`;
a DNS query for the name; proxy or firewall logs if egress goes through
one. The attacker can use a self-hosted capture server on their own domain
to avoid any known list.

## Prerequisites
A way to make the server send a request (an SSRF bug, command execution)
and outbound internet access from the server.

## Mapping
T1567.004 Exfiltration Over Webhook, tactic exfiltration. When the
callback only confirms a bug and carries no data, the activity is closer
to testing for T1190; the rule cannot tell the two apart and maps to the
technique ATT&CK ties to webhook.site. T1071.001 Web Protocols (command
and control) was not used: these services relay requests to the attacker,
not commands back. Checked against the enterprise bundle (mitre/cti
master, fetched 2026-11-07).

## References
- Microsoft Threat Intelligence, "ARTEX abuse expands as cybercriminals target financial sector", 2026-11-06, https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/ (fetched 2026-11-07)
- MITRE ATT&CK T1567.004
- ProjectDiscovery interactsh README (commit b9fea16, fetched 2026-11-07)
