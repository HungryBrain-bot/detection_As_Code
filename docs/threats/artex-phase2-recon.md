# ARTEX-style agentic attacks, Phase 2: recon

Written 2026-11-07 for the owner's blog series. Phase 2 is how an agent
maps an application and probes cloud permissions. Phase 1 (credential
sourcing) is in [artex-phase1-credential-sourcing.md](artex-phase1-credential-sourcing.md).
This file maps each place the blog draft suggests a detection to what
was built, records which of the draft's factual claims the sources
support, and keeps the hardening and planting guidance the draft gives.
Later phases are not covered.

## What was built

| Blog draft says | Built | Type |
|---|---|---|
| Plant a decoy route (`/api/internal/v1/export-customers`) in the OpenAPI spec or a JS bundle; any request is a high-confidence alert | [D1](../../detections/recon/D1-T1595-decoy-route-hit/) (route paths are `DecoyRoute` rows in `Honeytoken_CL`; how to plant one is in D1's README) | Rule, T1595 + T1594 |
| Same client fetches `.map`, `swagger.json`, config files, then within minutes calls routes the front-end does not normally call | [D2](../../detections/recon/D2-T1594-docs-then-novel-api/) (per-app UI baseline learned from traffic; two other ways described, not built) | Rule, T1594 + T1595 |
| One client, dozens of distinct paths in minutes, high share of 401/403/404 | [D3](../../detections/recon/D3-T1595.003-failing-path-sweep/) | Rule, T1595.003 |
| Bursts of `AccessDenied` / `UnauthorizedOperation` in CloudTrail from one principal within about a minute across several services | [D4](../../detections/recon/D4-T1580-cloud-permission-burst/) (AWS only) | Rule, T1580 |
| Same, 403s in Azure Activity | **Not built** | The Activity log "doesn't typically capture read operations" (Microsoft Learn, fetched 2026-11-07), which are the calls an enumerator makes; how it records a 403 authorization failure was not found in the fetched pages. A rule would be written from a guess. Parked in BUILD_LOG.md |
| Hardening: no source maps in production, auth on Swagger, no secrets in runtime config, server-side authorization | Guidance below | Not rules: they are changes to the app |

All four rules are `status: test`, `targeted`, Sentinel only. D1 to D3
read `AppServiceHTTPLogs` (Azure App Service only; Application Gateway,
Front Door and other web logs have no reference schema here). They pass
in the Kusto emulator on hand-written samples; no recorded web access
log is loaded. D4 also ran on three recorded CloudTrail sets (Splunk
attack_data): 11 rows, all one scanner user, none for the ordinary users
in the same files. None has run on a real tenant. Design decisions are
in ADR 010.

Why the ATT&CK IDs: the owner's suggestions were checked against the
enterprise bundle (mitre/cti master, fetched 2026-11-07; none revoked or
deprecated). T1595 / T1595.003 / T1594 (reconnaissance) fit the web
rules; T1580 (discovery) fits D4. T1592 (Gather Victim Host Information)
was not used (the downloaded files give application routes, not host
information). T1526 and T1087 were not used for D4: T1526 is service
discovery "after gaining access" and the rule cannot tell it from T1580;
T1087.004 is about accounts. T1190 is where the probing may lead, not
what the rules see.

## Claims in the draft, checked against sources (2026-11-07)

Sources fetched: the Wiz post (read in full), Microsoft's 2026-10-21
Storm-0940 report (verbatim only for its first 39,865 of 63,314
characters; the rest came through a summary and is not quoted here),
CrowdStrike (2026-10-07), Zscaler (2026-10-14) and Recorded Future
(2026-10-16) reports, AWS and Microsoft log documentation. All pages came
through a fetch tool, so quotes were not checked character by character.

| Claim in the draft | Status | Source and what it says |
|---|---|---|
| Wiz saw ARTEX agents download a target's JS bundles, source maps, runtime config and Swagger/OpenAPI documentation | **Supported, with a wording caveat** | Wiz 2026-10-22: the playbook step downloads "JavaScript bundles, exposed source maps, runtime configurations, and Swagger/OpenAPI documentation" to "discover internal API routes and application functionality"; "The agent's first move across all observed instances of the attack was always to read the application itself." Wiz says its observations "overlap with Microsoft's recent report on Storm-0940" and that the actor uses "tooling associated with ARTEX". That is overlap, not an assessment |
| The files are `*.js.map`, `/swagger.json`, `/openapi.json`, `/v2/api-docs`, `config.json`, `env.js`, `runtime-config` | **Partly** | Wiz's log shows only `GET /packs/js/main-3a9f...js.map`, `/assets/config.json`, `/env.js` and `/swagger/?format=openapi`. `swagger.json`, `openapi.json`, `v2/api-docs` and the string `runtime-config` are not named. Present them as typical paths, not as what Wiz saw. D2's pattern covers the owner's list and Wiz's paths |
| The agent then extracts internal API routes "that the front-end never shows to users" | **Partly** | Wiz: "Not long after, it started calling internal API routes by name." and "The only place those route names appear is in the source maps it had just downloaded." Wiz does not say the front-end hides them; "never shows" is the draft's wording (and consistent with the second quote) |
| Worker agents start testing those routes right away; findings go into a shared graph | **Partly** | Wiz: a planner chooses steps, "worker agents run tools like nmap, curl, and Impacket", results feed "a shared graph of assets and findings"; routes are "called by name minutes after pulling the source maps". "Right away" is "minutes" in the source. The Wiz post does not say worker agents tested those routes specifically |
| In the cloud, recon means testing permissions: the agent runs through every check it has, very quickly | **Not supported by the fetched sources** | The Wiz post does not contain CloudTrail, AccessDenied, UnauthorizedOperation, Azure or IAM enumeration. Microsoft's verbatim part says Storm-0940 "enumerated cloud resources and read secrets at scale across multiple Azure Key Vaults" and names an alert `KV_AccountVolumeAccessDeniedAnomaly`; it says nothing about AWS permission checks. CrowdStrike, Zscaler and Recorded Future: nothing on cloud enumeration. D4 detects the behavior of cloud enumeration tools in general (recorded cloudsploit and cloudmapper data), not a behavior shown for ARTEX |
| Real users load the page and call the APIs the UI needs; an agent's requests run in a different order | **Inference, consistent with Wiz's log** | Wiz's log shows the documents first and the routes minutes later. No source compares real-user traffic with agent traffic |
| A single client hitting dozens of paths in a few minutes with a high share of 401/403/404 | **Partly** | Wiz: "bombarded more than 60 variations of SSO routes with this payload in just two minutes"; about one request per second; a baseline `GET /zzz-nonexistent-xyz123` before every fuzzing run; sample lines answered 403 and 401. No error share is given. D3's 30 paths / 5 minutes / 70 percent are this project's thresholds |
| A decoy route is a high-confidence alert and shows the attacker is still in recon | **Inference** | No source reports an agent requesting a decoy route. The argument rests on Wiz's finding that routes are called by name from the downloaded files. A human tester who read the spec triggers it too, and so does a spec-driven API test tool |
| Bursts of AccessDenied / UnauthorizedOperation in CloudTrail within about a minute across several services | **Behavior real, ARTEX link not shown** | Recorded data (Splunk attack_data, cloudsploit and cloudmapper, 2021) has both `AccessDenied` and `Client.UnauthorizedOperation`, up to 612 denied calls in one minute and up to 36 services in one minute. AWS documents `errorCode` as "The AWS service error if the request returns an error" and `errorMessage` as including "messages for authorization failures"; the AWS page does not list these two codes. Wiz names a rule "Unusual Mass Access Denied Activity" without saying for which platform |
| Many 403s in Azure Activity from one principal | **Not supported** | Activity log: "doesn't typically capture read operations"; no 403 representation found. No rule built |
| The Korean intrusions came through IDOR and broken authorization on less-protected portals | **Not supported as written** | Zscaler: ARTEX agents "identified and exploited vulnerabilities including SQL injection and authentication bypass" in "peripheral internet-facing web applications, including customer-facing inquiry portals". CrowdStrike (citing industry reporting): a "loan progress inquiry service used by financial brokers" and an "employee mobile work-support system". Recorded Future gives no vector. None of the three uses IDOR or "broken authorization" for the Korean cases. Zscaler's recommendation 7, "Enforce server-side authorization for access to customer records", is advice, not an observed technique. Wiz does describe probing "predictable identifiers" for "broken access controls", with `GET /company/1/logins` answered 403, but for its own (software-vendor) victims, and it ties its Korean-bank mention to ARTEX artifacts only. Suggested wording: "the Korean intrusions exploited peripheral web portals (Zscaler reports SQL injection and authentication bypass); Wiz saw ARTEX probe for broken access control on other victims" |
| ARTEX is attributed to Storm-0940 | **Partly** | Microsoft 2026-10-21: "Microsoft assesses that Storm-0940 was responsible for the recently disclosed ConnectWise supply chain compromise", "a China-state aligned actor". Wiz: overlap only, and "Microsoft and Zscaler have since tied it to two separate actors." Recorded Future calls the Korean actor TAG-217; CrowdStrike and Zscaler leave it unnamed. Do not write that Storm-0940 hit the Korean banks |
| Wiz post title: Storm-0940 "expands targeting" of IT and software vendors | Supported | Wiz title and text: "multiple IT and software vendors", "expanding their attempted supply chain compromises into other software sectors" |

### Update to the Phase 1 table (nothing there was edited)
Phase 1 listed two ARTEX claims as unverified. The Wiz post, fetched now,
says the developer "made the tool closed-source on October 8" and that it
had "more than 12,000 forks", and that it was "published ... on GitHub in
July 2026". Microsoft's 2026-10-21 report still calls ARTEX "an open-source
penetration testing framework". Go as the language, Hexstrike and CAIRN
are still not in any fetched source.

## Hardening guidance (the draft's, not rules)

These are the draft's recommendations. They are standard practice; none
of the fetched sources measures whether they stop ARTEX. Wiz's post lists
no hardening controls, and Zscaler lists server-side authorization for
customer records.

- **No source maps in production.** Upload them to the error-tracking tool instead of serving them. Check the build output and the live site (`curl -I https://app.example/static/js/main.js.map`). This removes the first leg of D2 and the source of route names Wiz describes. If a route name is still in the minified bundle, the agent can still extract it.
- **Authentication on Swagger / OpenAPI**, or take the documents off public hosts. Effect on the rules: a document answered 401 is not "downloaded" for D2, so D2 stops firing, which is the intended result; D1 and D3 remain.
- **Nothing that looks like a secret in runtime config** (`env.js`, `config.json`): internal hostnames, tenant and client ids, feature flags are what an attacker wants from them. These files are fetched by every real visitor, so they cannot be put behind authentication; they can only be made boring.
- **Server-side authorization on every route.** Hiding a route in the UI does not stop anyone calling it. Check object-level authorization (the caller may read this record) as well as route-level, which is what IDOR-style probing tests.
- A decoy route (D1) works with all of the above: it adds a tripwire to what you still publish, and it matters most once the maps are gone and the bundle is the only source of route names.

## Not built, parked in BUILD_LOG.md
- An Azure branch for D4 (Activity log lacks reads; 403 representation unverified). Key Vault AccessDenied bursts in `AzureDiagnostics` are a separate rule.
- Other web logs: Application Gateway (the access-log field list came through a summary; whether `requestUri` includes the query string is not stated), Front Door, IIS / nginx.
- Mapping Splunk attack_data's web access logs for D3 background.
- A build-time route registry for D2's baseline.

## Sources
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors
- Microsoft Threat Intelligence and Microsoft Security Research, "AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise", 2026-10-21, https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
- CrowdStrike, https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/ (2026-10-07).
- Zscaler ThreatLabz, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (2026-10-14).
- Recorded Future (Insikt Group), https://www.recordedfuture.com/blog/tag-217-artex-south-korean-banks (2026-10-16).
- Microsoft Learn: Azure Monitor activity log; AppServiceHTTPLogs, AWSCloudTrail and AzureActivity table references.
- AWS CloudTrail record contents, https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- Azure-Sentinel repository, commit c0c2dc2, `Sample Data/Tables/AWSCloudTrail/metadata.json`.
- Splunk attack_data, commit b52ee68, T1580 and T1526 directories (Apache-2.0).
- MITRE ATT&CK enterprise bundle (mitre/cti master).
All fetched 2026-11-07.
