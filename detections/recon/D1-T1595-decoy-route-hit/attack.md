# Reading a published API map and probing its routes (T1595, T1594)

## What the attack is
The attacker obtains the list of an application's API routes from what
the application itself publishes (a JavaScript bundle, a source map, a
Swagger / OpenAPI document), then probes those routes. It costs the
attacker nothing the app does not already give away, and it shows them
routes the UI never links to.

## How the attack happens
1. Fetch the page and its scripts; fetch source maps (`*.js.map`) and
   runtime config (`/env.js`, `/assets/config.json`); fetch API docs
   (`/swagger/`, `/openapi.json`, `/v2/api-docs`).
2. Extract route strings from the code and the docs.
3. Request each route, with and without credentials, and note which
   answer differently (200, 401, 403, 405) from a non-existent path.
4. Test the interesting ones for missing authorization (changing ids,
   skipping the UI's access checks).
Tools: curl and Python HTTP clients scripted by hand or driven by an
agent; open-source testing frameworks that run such tools (ARTEX, per Wiz).

## Real-world use
Wiz (2026-10-22) reports an ARTEX-using actor, overlapping with
Microsoft's Storm-0940, whose "first move across all observed instances
of the attack was always to read the application itself". Its log shows
a `.js.map` file, `/assets/config.json`, `/env.js` and
`/swagger/?format=openapi`, and "internal API routes are called by name
minutes after pulling the source maps". Wiz describes this as a pattern
in its victims' HTTP logs; it does not say decoy routes were tried. Full
claim check: docs/threats/artex-phase2-recon.md.

## What it leaves in the logs
Web access logs: one request per route, with the path, status, client
IP and user agent (App Service: `AppServiceHTTPLogs`: `CsUriStem`,
`ScStatus`, `CIp`, `UserAgent`). A decoy route leaves a request to a
path that exists only in the spec. The attacker controls the user agent
and the source IP, and can slow down or spread requests; they cannot
avoid the access log unless a front layer drops it.

## Prerequisites
A reachable web application that publishes its routes. No credentials
are needed for the reading step.

## Mapping
T1595 Active Scanning (the probing) and T1594 Search Victim-Owned
Websites (reading the app's own published material), tactic
reconnaissance; the parent T1595 rather than T1595.002 (Vulnerability
Scanning) because the rule detects probing of a route, not a
vulnerability test, and rather than T1595.003 (Wordlist Scanning)
because the paths come from the target's own spec, not a wordlist. IDs
checked against the ATT&CK enterprise bundle (mitre/cti master,
fetched 2026-11-07); none revoked or deprecated.

## References
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- MITRE ATT&CK T1595, T1594, https://attack.mitre.org/ (bundle fetched 2026-11-07).
