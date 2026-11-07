# Stolen service principal secret used alongside the real app (T1078.004)

## What the attack is
When an app's client secret leaks, the attacker does not replace the
app: the real app keeps signing in with the secret from where it runs,
and the attacker signs in with the same secret from their own
infrastructure. For a while, one credential is in use by two parties
at once. Nothing at sign-in looks wrong: no MFA, no failed login.

## How the attack happens
1. The secret leaks (public repo, `.env`, CI logs) and is found by a
   search such as those in docs/hunts/H1-leaked-secrets-self-search.md.
2. The attacker requests tokens with the client credentials grant from
   a VPS, proxy or VPN exit, often rotating IP addresses.
3. Meanwhile the app, hosted in Azure App Service, AKS or a VM, keeps
   requesting tokens with the same secret from Microsoft's network.
4. Entra logs both in `AADServicePrincipalSignInLogs`, with the same
   `ServicePrincipalCredentialKeyId`, the id of the secret or
   certificate that was used.

## Real-world use
- Microsoft (2026-11-05) reports agentic tooling finding client secrets
  on GitHub and using them against Entra ID and Key Vault. Its
  indicators include an attacker IP it says "is a Tor exit node", and it
  recommends watching "authentication attempts from anonymized or
  high-risk infrastructure". It does not describe this two-network
  check; the check is this project's (and the blog draft's) inference
  from how hosted apps authenticate.

## What it leaves in the logs
`AADServicePrincipalSignInLogs`: `ServicePrincipalCredentialKeyId`,
`AutonomousSystemNumber`, `IPAddress`, `ResultType`, `ServicePrincipalId`,
`AppId`, `ResourceDisplayName`. The attacker controls the IP and the
network they come from, but cannot originate traffic from inside the
customer's own Azure estate without first compromising it.

## Prerequisites
A leaked client secret or certificate for a service principal whose
real workload runs in Azure (AS8075). An attacker who hosts their
tooling in Azure defeats this rule (Blind spots).

## Mapping
T1078.004 Valid Accounts: Cloud Accounts, initial-access: the service
principal is a cloud account and the attacker uses its valid
credential. Not T1550.001 (application access token reuse): the
attacker holds the secret and mints new tokens. Checked against
ATT&CK 20.1 (2026-11-07).

## References
- Microsoft, "Threat actors use agentic AI tooling to find and abuse
  exposed secrets", 2026-11-05,
  https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
  (fetched 2026-11-07 through a fetch tool).
- Microsoft Learn, "Internet peering overview" (last updated
  2026-02-25): "Microsoft's global network (AS8075)",
  https://learn.microsoft.com/en-us/azure/internet-peering/overview
  (fetched 2026-11-07); PeeringDB net record for AS8075, "Microsoft"
  (fetched 2026-11-07).
- `AADServicePrincipalSignInLogs` columns: Microsoft Learn table
  reference (last updated 2026-08-28) and Azure-Sentinel sample
  metadata at c0c2dc2 (fetched 2026-11-07).
