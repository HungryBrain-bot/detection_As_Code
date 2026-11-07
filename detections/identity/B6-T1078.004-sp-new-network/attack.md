# Stolen service principal secret used from new infrastructure (T1078.004)

## What the attack is
The same leaked-secret attack as B4 and B5, seen from a different
angle: whether or not the real app is still running, the attacker's
sign-ins come from networks the app has never used. Attackers rotate
IP addresses freely, so a per-IP baseline is useless, but rotating
inside one VPS provider, proxy service or Tor still leaves them in a
small set of autonomous systems the app has not used before.

## How the attack happens
1. The attacker obtains a client secret (T1593.003 / T1552.001).
2. Their tooling requests tokens from a VPS, residential proxy, VPN or
   Tor, changing IP between attempts.
3. Each sign-in is logged in `AADServicePrincipalSignInLogs` with the
   source `IPAddress` and `AutonomousSystemNumber`.
4. The app's own sign-ins have come for weeks from one or two ASNs
   (Azure, a data centre); the attacker's come from a new one.

## Real-world use
- Microsoft (2026-11-05) lists the attacker infrastructure in its
  agentic-secret-abuse case, including an IP it says "is a Tor exit
  node", and advises to "Block the exact IP rather than the whole ASN"
  when containing. That advice is about blocking; for detection this
  rule takes the opposite granularity on purpose (Why this logic).
- No fetched report measures how often attackers come from an ASN the
  victim app never used.

## What it leaves in the logs
`AADServicePrincipalSignInLogs`: `AutonomousSystemNumber`, `IPAddress`,
`ServicePrincipalId`, `AppId`, `ResultType`, `ResourceDisplayName`,
`ServicePrincipalCredentialKeyId`.

## Prerequisites
A leaked secret, and an app with at least 10 successful sign-ins in
the previous 14 days (the rule's baseline). New apps are not judged.

## Mapping
T1078.004 Valid Accounts: Cloud Accounts (initial-access), as B5.
Checked against ATT&CK 20.1 (2026-11-07).

## References
- Microsoft, "Threat actors use agentic AI tooling to find and abuse
  exposed secrets", 2026-11-05,
  https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
  (fetched 2026-11-07 through a fetch tool).
- Microsoft Learn, "Internet peering overview", AS8075
  (fetched 2026-11-07).
