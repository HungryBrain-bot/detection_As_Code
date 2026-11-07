# Probing many routes and keeping the ones that answer (T1595.003)

## What the attack is
The attacker requests a large number of paths, from a wordlist or from
routes extracted from the target's own scripts, and keeps those that do
not answer like a missing page. It finds routes, admin pages and API
endpoints that nothing links to.

## How the attack happens
1. Probe a path that cannot exist (Wiz's log shows `GET /zzz-nonexistent-xyz123`) to learn what "not found" looks like for this app.
2. Request many paths quickly: hundreds of routes from a list, or variants of one route (Wiz: "more than 60 variations of SSO routes with this payload in just two minutes").
3. Compare each answer with the baseline "not found" and keep those that differ (200, 401, 403, 405).
Common tools: ffuf, gobuster, dirsearch, feroxbuster, nuclei and scripted Python or curl clients. The fetched ARTEX reports name curl and Python HTTP clients (Microsoft: "by default uses Nmap, curl, wget, Python HTTP clients", per the Phase 1 doc) and the user agents `python-requests`, `Python-urllib` and `curl` (Wiz, Microsoft); they do not name ffuf or gobuster.

## Real-world use
Wiz (2026-10-22) reports a request rate of "about one request per second" and median one-second gaps between authentication attempts for an ARTEX-using actor, and logs `GET /company/1/logins` answered 403 and `GET /api/users/generate_redirect_link?role=admin` answered 401. It gives no share of failing responses. No page fetched for CrowdStrike, Zscaler or Recorded Future (Korean banks) mentions request rates or response codes; Zscaler lists "High-frequency automated HTTP requests with sequential enumeration patterns against login and search endpoints" as a behavioral indicator. See docs/threats/artex-phase2-recon.md.

## What it leaves in the logs
Web access log: many requests from one IP with many distinct paths and a high share of 404, 403, 401. `AppServiceHTTPLogs`: `CIp`, `CsUriStem`, `ScStatus`. The attacker controls speed, user agent, source IPs and the order of paths; a slow, distributed sweep looks like background noise.

## Prerequisites
A reachable web host. No credentials.

## Mapping
T1595.003 Wordlist Scanning ("iteratively probe infrastructure using brute-forcing and crawling techniques", ATT&CK; its aim is "the identification of content and infrastructure rather than the discovery of valid credentials"), tactic reconnaissance. It is not T1110 Brute Force: the aim is finding routes, not credentials. Checked against the ATT&CK enterprise bundle (mitre/cti master, fetched 2026-11-07).

## References
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Zscaler ThreatLabz, "Threat Actor Abuses Agentic AI Pentesting Framework to Target South Korean Financial Institutions", 2026-10-14, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (fetched 2026-11-07).
