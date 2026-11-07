# Leaked app secret used against Entra ID and Key Vault (T1078.004, T1555.006)

## What the attack is
An attacker finds an Entra ID app registration's client secret (with
its tenant id and client id) in a public code repository, a `.env`
file or a CI log, and signs in as that service principal. App-only
sign-ins have no MFA and no interactive prompt, so Entra sees an app
authenticating normally. If the app can read a Key Vault, the attacker
lists and reads its secrets and keys, which are often more credentials.

## How the attack happens
1. The attacker searches public code for the target's name together
   with secret-like keywords (the self-hunt runbook,
   docs/hunts/H1-leaked-secrets-self-search.md, runs the same searches
   defensively).
2. A found `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET`
   triple is tried against the token endpoint
   (`login.microsoftonline.com/<tenant>/oauth2/v2.0/token`, client
   credentials grant) with `az login --service-principal`, an Azure SDK,
   or plain HTTP (`curl`, `python-requests`).
3. With a token, the attacker enumerates what the app can reach
   (subscriptions, resource groups, vaults) and calls Key Vault:
   `VaultGet`, `SecretList`, `SecretGet`, `KeyList`.
4. Agentic tooling runs steps 2 and 3 without a human pause, and tries
   every credential it finds.

A honeytoken is a decoy app registration whose secret is planted where
an attacker looks, plus decoy Key Vault secrets. Nothing legitimate
uses them, so any sign-in or read is the attack above.

## Real-world use
- Microsoft (2026-11-05, reference below) reports threat actors using
  agentic AI tooling to search GitHub for exposed secrets and abuse
  them, and in one case observed "an AI agent advance from scanning
  GitHub for secrets to exfiltrating data from Azure Key Vault in just
  five minutes". The same post names ARTEX as the agentic offensive
  framework and lists "Microsoft Sentinel Deception" (the HoneyTokens
  solution) under defensive decoys. It does not say a honeytoken caught
  this actor; that use is this rule's hypothesis.
- No report was fetched that measures how often attackers, or agents
  specifically, try planted credentials.

## What it leaves in the logs
- `AADServicePrincipalSignInLogs`: one row per app-only sign-in, with
  `AppId`, `ServicePrincipalCredentialKeyId` (which secret or
  certificate), `IPAddress`, `AutonomousSystemNumber`, `ResultType`
  (`0` success; Microsoft names AADSTS7000215 invalid secret and
  AADSTS7000222 expired secret) and `ResourceDisplayName`.
- Key Vault `AuditEvent` diagnostic logs, in `AzureDiagnostics` when
  the vault uses Azure Diagnostics mode: `OperationName`
  (`SecretGet`, `SecretList`, ...), `id_s` (object URI),
  `requestUri_s`, `identity_claim_appid_g` (caller app),
  `CallerIPAddress`, `clientInfo_s`, `ResultType`.
- The attacker cannot suppress these without already holding rights to
  change diagnostic settings; the Sentinel HoneyTokens solution has a
  separate rule for deleted or changed diagnostic settings (not
  reproduced here).

## Prerequisites
- For the attacker: the secret, from T1593.003 (code repositories) or
  T1552.001 (credentials in files).
- For the defender: a decoy app registration with a secret, ideally a
  read role on a decoy vault so the attacker continues to the second
  tripwire; decoy secrets with plausible names; registry rows in
  `Honeytoken_CL`; Key Vault diagnostic logs to the workspace.

## Mapping
- T1078.004 Valid Accounts: Cloud Accounts (initial-access): the
  service principal sign-in with a stolen secret. Not T1528 (Steal
  Application Access Token): the attacker steals the secret and mints
  their own token.
- T1555.006 Credentials from Password Stores: Cloud Secrets Management
  Stores (credential-access): reading Key Vault secrets. MITRE's page
  names Azure Key Vault.
- Not mapped: T1593.003 / T1552.001, how the secret was found; that
  happens outside the customer's logs.
- Checked against the enterprise STIX bundle (ATT&CK 20.1, fetched
  2026-11-07).

## References
- Microsoft Threat Intelligence and Microsoft Security Research, "Threat
  actors use agentic AI tooling to find and abuse exposed secrets",
  2026-11-05,
  https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
  (fetched 2026-11-07 through a fetch tool; quotes here were not checked
  character by character against the page).
- Microsoft Sentinel Deception (HoneyTokens) solution README, Azure-Sentinel
  repo at c0c2dc2, https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/HoneyTokens
  (read with git, 2026-11-07): plants "decoy Azure Key Vault keys and
  secrets, called honeytokens"; "there is no legitimate reason to access
  a honeytoken".
- MITRE ATT&CK T1078.004, T1555.006: enterprise-attack.json, ATT&CK 20.1
  (fetched 2026-11-07).
