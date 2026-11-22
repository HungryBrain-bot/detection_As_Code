# An agent requests routes taken from a published spec or bundle, on AWS (T1595, T1594)

## What the attack is
Same attack as [D1](../D1-T1595-decoy-route-hit/attack.md): an attacker,
or an agent working for one, downloads an app's OpenAPI spec, source
maps or JavaScript bundle, extracts the API routes, and calls them by
name. Here the app runs on AWS behind AWS WAF.

## How the attack happens
1. The tool downloads the published documents (spec, bundle, maps).
2. It extracts route paths, including ones the UI does not use.
3. It calls those routes directly, often within minutes.
4. A decoy route planted in the spec or the bundle is among them.

## Real-world use
- Wiz (2026-10-22) saw ARTEX agents download a target's bundles, source
  maps, config and Swagger/OpenAPI documents and then call "internal API
  routes by name" (see docs/threats/artex-phase2-recon.md). Wiz's post
  does not say where those apps were hosted.
- **No fetched source shows ARTEX against an app on AWS, or any agent
  requesting a decoy route.** This rule detects the behaviour on AWS;
  it is not evidence that ARTEX does it there.

## What it leaves in the logs
`AWSWAF`: one row per request the web ACL evaluated, with the request in
`HttpRequest` (`clientIp`, `uri`, `args`, `headers`, `httpMethod`,
`host`), the WAF `Action`, `HttpSourceName` / `HttpSourceId` (which
CloudFront distribution, load balancer or API stage) and `WebAclId`.

## Prerequisites
A decoy route planted in what the app publishes (D1's README says how),
listed in `Honeytoken_CL`; a web ACL in front of the app with logging to
S3 and Sentinel's AWS WAF connector.

## Mapping
T1595 Active Scanning (requests to the target's routes) and T1594 Search
Victim-Owned Websites (the routes come from the victim's own published
documents). Same mapping as D1. IDs checked with `python -m dac validate
--attack-bundle` on 2026-11-21.

## References
- See README.md, References.
