# Server connects to a request-capture service (webhook.site, interactsh)

ATT&CK: T1567.004 · Severity: High · Status: experimental · Tier: targeted · Targets: sentinel

## Hypothesis
Request-capture services give anyone a URL or DNS name that records every
request sent to it. Production servers have no reason to contact them, so
a connection from a server to one of these domains suggests someone is
testing whether the server can be made to call out, or sending data out.

## Data sources
- `mde-advanced-hunting` (endpoint team): `DeviceNetworkEvents`
  (`RemoteUrl`, `RemoteIP`, initiating process) and `DeviceInfo`
  (`OSPlatform`, `DeviceType`). Column names and types from Microsoft's
  Azure-Sentinel repo table definitions (commit c0c2dc2, read directly).
- Prerequisite: Defender for Endpoint on the servers, streamed to Sentinel
  by the Defender XDR connector. A connection with no `RemoteUrl` (IP
  only, or the sensor did not resolve a name) is not seen.
- `OSPlatform` values (`WindowsServer2022`, `Linux`) and `DeviceType`
  `Server` are assumed from Defender's usual values; they were not checked
  against a live tenant.

## Detection logic
```kql
// see rule.yaml for the full query
```
1. Servers: latest `DeviceInfo` row per device where `OSPlatform` starts
   with `WindowsServer`, is `Linux`, or `DeviceType` is `Server`.
2. Last hour of `DeviceNetworkEvents` with a `RemoteUrl`; take the host
   part, lower case.
3. Keep hosts equal to a listed domain or under it (`x.oast.pro`), not
   look-alikes (`notwebhook.site`, `webhook.site.example.test`).
4. Join to servers and report device, URL, IP and the process that made
   the connection.

## Why this logic
- Exact domain or subdomain match, not substring: substring would match
  look-alike names.
- Servers only, as the owner's draft says: developers use these services
  from laptops for webhook testing. Linux is treated as a server because
  most Linux devices onboarded to Defender are.
- Domain list as a parameter (`capture_domains`), not a watchlist: the
  harness has no watchlist function; customers can switch it to
  `_GetWatchlist(...)` in Sentinel.
- Default domains are only those confirmed from the services' own pages:
  `webhook.site` and `dnshook.site` (webhook.site home page), and
  `oast.pro`, `oast.live`, `oast.site`, `oast.online`, `oast.fun`,
  `oast.me` (ProjectDiscovery interactsh README, commit b9fea16). Burp
  Collaborator's public domain was not named on the PortSwigger page
  fetched, so it is not in the default list; add it if confirmed.
- Alternative, DNS logs: catch lookups even when no connection is made
  (DNS-only callbacks), but DNS logging is not a declared source here;
  parked.

## False positives
- Integration testing on servers in non-production environments.
- Security scanners and penetration tests that use interactsh on purpose.
- Monitoring that calls a webhook.site URL by design (rare; fix the
  monitoring).

## Tuning
- Add services you see in your own logs to `capture_domains`; candidates
  not verified here include RequestBin, Pipedream and Burp Collaborator.
- No samples have been run.

## Test evidence
Not run. No positive or negative samples exist and the query has not been
executed in the Kusto emulator. The recorded WSUS dataset pinned for E3
contains `curl.exe` posting to `webhook.site`, but as a Sysmon process
event, not a Defender network event, so it cannot exercise this rule. The
rule is `experimental`, so it is deployed disabled. See
[tests/evidence.md](tests/evidence.md).

## Blind spots
- Self-hosted request-capture servers on the attacker's own domain.
- Connections through a proxy where the sensor records only the proxy.
- Callbacks made by a different system (the SSRF target, a cloud service)
  rather than the server Defender is on.
- Devices whose `DeviceInfo` does not say server.

## References
- MITRE ATT&CK T1567.004 Exfiltration Over Webhook (names `webhook.site`), enterprise bundle fetched 2026-11-07
- ProjectDiscovery interactsh README, https://github.com/projectdiscovery/interactsh (commit b9fea16, fetched 2026-11-07)
- Webhook.site, https://webhook.site (fetched 2026-11-07)
- Splunk attack_data T1505.003/wsus-windows-sysmon.log at commit b52ee68 (Apache-2.0)
- docs/threats/artex-phase4-foothold.md; ADR 012
