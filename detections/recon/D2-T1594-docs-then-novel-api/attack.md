# Mapping an application from its own scripts and API documents (T1594, T1595)

## What the attack is
The attacker reads the files an application publishes about itself
(source maps, runtime config, Swagger / OpenAPI) to learn its internal
API routes, then calls routes the UI never uses. It turns the app's
public front-end into a map of the backend, in minutes.

## How the attack happens
1. Download the page's scripts and their source maps (`main.<hash>.js.map`), which contain the original source, route names and comments.
2. Download runtime configuration (`/assets/config.json`, `/env.js`), which can carry internal hostnames, tenant and client ids and feature flags.
3. Download API documents (`/swagger/`, `/swagger.json`, `/openapi.json`, `/v2/api-docs`), which list every endpoint, parameter and auth scheme in machine-readable form.
4. Call the extracted routes, in particular admin and internal ones, and note the responses.
ARTEX (open-source, per Microsoft; closed-sourced by its developer on 2026-10-08, per Wiz) drives scripted tools (nmap, curl, Impacket) with a planner and worker agents.

## Real-world use
Wiz (2026-10-22): "The agent's first move across all observed instances of the attack was always to read the application itself." Its log excerpt shows a source map, `/assets/config.json`, `/env.js` and `/swagger/?format=openapi`, then "internal API routes are called by name minutes after pulling the source maps". The route names are found in the source maps ("The only place those route names appear is in the source maps it had just downloaded", Wiz). The Wiz post attributes the activity to an actor whose observations "overlap with Microsoft's recent report on Storm-0940". CrowdStrike, Zscaler and Recorded Future (Korean banks, 2026-10) do not mention these downloads in the pages fetched. See docs/threats/artex-phase2-recon.md.

## What it leaves in the logs
In the web access log: GET requests for `*.map`, config and spec paths from one client, followed by requests to API paths. Table and columns: `AppServiceHTTPLogs` (`CIp`, `CsHost`, `CsUriStem`, `ScStatus`, `UserAgent`). The attacker controls user agent, speed and source IP. Cached or CDN-served files may not reach the app's log.

## Prerequisites
A reachable application that serves its source maps, config or API documents without authentication.

## Mapping
T1594 Search Victim-Owned Websites (reading material the victim publishes) and T1595 Active Scanning (calling routes to see what answers), tactic reconnaissance. T1592 (Gather Victim Host Information) was considered and not used: the files give application routes, not host information. Checked against the ATT&CK enterprise bundle (mitre/cti master, fetched 2026-11-07).

## References
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Microsoft Threat Intelligence and Microsoft Security Research, "AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise", 2026-10-21, https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/ (fetched 2026-11-07; the page was read verbatim only for its first 39,865 of 63,314 characters)
