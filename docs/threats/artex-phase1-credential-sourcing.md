# ARTEX-style agentic attacks, Phase 1: credential sourcing

Written 2026-11-07 for the owner's blog series. Phase 1 is how an
agent finds and first uses secrets. This file maps each place the blog
draft suggests a detection to what was built, and records which of the
draft's factual claims the cited sources support. Later phases (recon,
identity attacks, exploitation, ...) are not covered.

## What was built

| Blog draft says | Built | Type |
|---|---|---|
| Search for your org name plus `client_secret`, `tenant_id`, `AZURE_OPENAI`, `.env`; turn on secret scanning and push protection; rotate | [H1](../hunts/H1-leaked-secrets-self-search.md) | Hunt / runbook (no rule possible: the attacker's search is not in the customer's logs) |
| Set a honeytoken trap | [B4](../../detections/identity/B4-T1078.004-honeytoken-credential-use/) | Rule, T1078.004 + T1555.006 |
| One `ServicePrincipalCredentialKeyId`, two places at once | [B5](../../detections/identity/B5-T1078.004-credential-two-networks/) | Rule, T1078.004 |
| A new type of network (ASN, not IP) | [B6](../../detections/identity/B6-T1078.004-sp-new-network/) | Rule, T1078.004 |
| Doesn't behave like your app (new client, `List*` / `/users` enumeration, fix-and-retry in about a minute) | [B7](../../detections/identity/B7-T1087.004-sp-unlike-its-app/) | Rule, T1087.004 + T1069.003 + T1526 |

All four rules are `status: test`: they pass in the Kusto emulator on
hand-written samples, and run without matching on the recorded Splunk
lab data. None has run on a real tenant, and none of the recorded data
exercises them (no ASN in the recorded service principal sign-ins, no
Key Vault logs, no Graph baseline). Treat them as untested against real
attacks. Design decisions are in ADR 009.

Not built from the draft: "new resources" in B7 is covered only for
Graph endpoints (not ARM resources); the draft's `List*` refers to Azure
Resource Manager list operations, which are not in `AzureActivity`
[Likely] and so have no rule here.

## Claims in the draft, checked against sources (2026-11-07)

Sources fetched: Microsoft's 2026-11-05 post (linked in the draft);
GitGuardian's State of Secrets Sprawl 2026 page; CrowdStrike
(2026-10-07), Zscaler (2026-10-14) and Recorded Future (2026-10-16)
ARTEX reports; the Azure-Sentinel HoneyTokens solution (read with git).
All web pages came through a fetch tool, so quotes were not checked
character by character.

| Claim in the draft | Status | Source and what it says |
|---|---|---|
| An AI agent went from searching GitHub to pulling data out of Key Vault in five minutes, in one case Microsoft described | Supported | Microsoft 2026-11-05: "an AI agent advance from scanning GitHub for secrets to exfiltrating data from Azure Key Vault in just five minutes" |
| Agents search for the org's name combined with secrets, cloud and AI-provider terms | Supported | Microsoft: queries "often included the name of a target organization, keywords for secrets, a keyword linked to cloud services, or a keyword linked to another AI service provider" |
| The terms are `client_secret`, `tenant_id`, `AZURE_OPENAI`, `.env` | **Not in the source** | Microsoft lists no literal terms. Present them as the author's suggestion, not Microsoft's finding |
| Agents especially want AI-service keys because a stolen key pays for the model | Partly | Microsoft names AI-provider keywords in the queries; "pays for the model running the attack" was not found in the post. Mark as the author's inference |
| GitGuardian: 28.65 million new hardcoded secrets on GitHub in 2025 | Supported, wording differs | GitGuardian page: 28,649,024, "New secrets detected in public GitHub commits in 2025". It says *public* commits and does not say "hardcoded" in that caption |
| AI-service secret leaks rose 81% | Supported | GitGuardian: "81%", "YoY growth of secrets of AI-related services" |
| No MFA prompt, no failed login: Entra sees an app authenticating | Consistent | Client credentials sign-ins have no MFA; Microsoft's detection advice is about sign-in errors and source infrastructure, not MFA |
| In March 2026 Microsoft said attackers used AI mainly to help human operators | **Not verified** | Not in the 2026-11-05 post; no March 2026 source was found or fetched. Needs its own link or should be cut |
| Google, Wiz, CrowdStrike and Microsoft all reported intrusions where agents ran most of the operation | **Not supported as written** | CrowdStrike reports ARTEX use but not that agents ran "most of the operation"; Recorded Future: "The available evidence does not establish the extent to which AI accelerated these attacks". Google and Wiz reports were not fetched |
| ARTEX is an open-source Go framework | Partly | Open source: CrowdStrike and Zscaler. Go: not stated in any fetched source |
| A planner agent decides; workers run nmap, curl, Impacket; findings in a shared graph | Partly | Zscaler: "The planner divides the engagement into tasks, while worker agents execute tools and store findings". Microsoft: ARTEX "by default uses Nmap, curl, wget, Python HTTP clients", among others. Impacket and "shared graph" not found |
| Works with whatever model the operator connects; one crew used cheap DeepSeek via a reseller | Partly | Zscaler: "The harness supported multiple LLM backends". CrowdStrike: "likely accessed DeepSeek via the likely LLM API proxy/reseller". "Cheap" not found; the sources describe one actor |
| The author made it closed source in October, by then 12,000+ forks | **Partly; fork count not verified** | Zscaler: the developer "made the project closed source" after disclosure, with no date. No source gives 12,000 forks |
| Hexstrike and CAIRN are similar tools seen in real attacks | **Not verified** | Not mentioned in any fetched source |
| Attack phases: credential sourcing, recon, identity, exploitation, C2, privesc, cloud abuse, exfiltration | Not a sourced list | The author's framing; Microsoft uses ATT&CK tactic names, not this sequence |
| A honeytoken is a reliable tripwire against agents | Inference | Microsoft lists "Microsoft Sentinel Deception" among defensive decoys; no source measures how often agents trigger one. Fine as an argument, not as a finding |
| Fix failed calls within about a minute | Supported | Microsoft: retries began about 28, 60 and 80 seconds after failures |
| Different client, e.g. python-requests instead of the SDK | Partly | Microsoft: tools "may send network traffic with distinctive characteristics, such as default user agent strings". `python-requests` is the author's example |
| One `ServicePrincipalCredentialKeyId` from two places; new network type by ASN | Author's detection ideas | Not in Microsoft's post (it advises blocking "the exact IP rather than the whole ASN" for containment). The column exists in `AADServicePrincipalSignInLogs` (Microsoft table reference) |

## Sources
- Microsoft Threat Intelligence and Microsoft Security Research, "Threat
  actors use agentic AI tooling to find and abuse exposed secrets",
  2026-11-05,
  https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- GitGuardian, "The State of Secrets Sprawl 2026",
  https://www.gitguardian.com/state-of-secrets-sprawl-report-2026
  (publication date not shown on the page).
- CrowdStrike, https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/ (2026-10-07).
- Zscaler, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (2026-10-14).
- Recorded Future, https://www.recordedfuture.com/blog/tag-217-artex-south-korean-banks (2026-10-16).
- Azure-Sentinel HoneyTokens solution, https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/HoneyTokens (commit c0c2dc2).
All fetched 2026-11-07.
