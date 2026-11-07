# Honeytoken app credential or decoy Key Vault object used

ATT&CK: T1078.004, T1555.006 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If an attacker (or an agent working for one) finds a planted decoy app
secret and tries it, Entra ID logs a service principal sign-in with the
decoy's `AppId`. If they reach Key Vault, the vault logs a read of a
decoy secret or a call made with the decoy app's identity. No
legitimate process uses either, so one event is enough to alert.

## Data sources
- `entra-sp-signin` (identity team): `AADServicePrincipalSignInLogs`.
- `azure-keyvault-audit` (cloud platform team): Key Vault `AuditEvent`
  in `AzureDiagnostics` (Azure Diagnostics mode).
- `honeytoken-registry` (detection team): `Honeytoken_CL`, defined by
  this project (ADR 009), one row per active decoy, re-sent at least
  hourly. `TokenType` is `ServicePrincipalAppId` or `KeyVaultObject`.
- If the sign-in table is missing, only the Key Vault half works, and
  the reverse. If the registry is not re-sent within the hour, the rule
  matches nothing: it fails silent, which is why the gate asks the
  detection team to confirm it.
- Tier targeted: it is only useful where decoys have been planted.

## Detection logic
1. Read the registry; split it into decoy app ids and decoy object
   names, lower-cased (`AppId` case varies between tables).
2. Sign-ins: any `AADServicePrincipalSignInLogs` row whose `AppId` is a
   decoy, whatever the result (a failed attempt with a decoy id is
   still someone trying it).
3. Key Vault: `AzureDiagnostics` rows from `MICROSOFT.KEYVAULT`,
   category `AuditEvent`; the object name is cut from `id_s` (or
   `requestUri_s`) as the segment after `/secrets/` or `/keys/`, and
   must equal a decoy name exactly. Also any Key Vault call whose
   caller app (`identity_claim_appid_g`) is a decoy app.
4. One row per decoy and surface, with operations, results, IPs, ASNs,
   caller app ids, credential key ids, the planted location from the
   registry, and first and last time.

## Why this logic
- Exact match on the decoy name, not `has` / `contains`: a real secret
  called `payments-db-admin-password-v2` must not alert (tested; with
  `has`, the near-name negatives match).
- Any result for sign-ins, not only successes: a decoy whose secret
  was rotated or expired still catches the attempt. Microsoft's
  guidance names invalid-secret and expired-secret errors as signals.
- A registry table, not a Sentinel watchlist: a watchlist
  (`_GetWatchlist`) is what the Sentinel HoneyTokens solution uses and
  is the better operational choice, but the harness's Kusto emulator
  has no `_GetWatchlist` (same choice as C2's canary table). Switching
  is a one-line change to the `honeytokens` let.
- Alternative: use the Sentinel HoneyTokens solution's own analytics
  rules. They cover Key Vault decoys only (that solution plants vault
  keys and secrets); they do not cover a decoy *app credential* planted
  in a repo, which is the case the ARTEX reporting describes. This rule
  covers both and can sit next to the solution.

## False positives
- Someone in the organisation tests or scans the decoy (red team,
  secret scanner validating a found secret, a curious engineer). These
  are true detections of the decoy being touched; triage confirms who.
- Backup or replication tools that read every secret in a vault
  (`SecretList` + `SecretGet` on all objects) will hit decoy secrets
  placed in a production vault. Put decoys in a vault those tools do not
  cover, or exclude their app id.
- Microsoft's own secret scanning partners may validate a leaked
  secret against Entra; whether that logs a sign-in was not checked.

## Tuning
- Negatives tested: non-decoy app, near-name and prefix-name secrets,
  the decoy name in a non-Key-Vault `AzureDiagnostics` record, an app id
  one character away from the decoy. Each was shown to match when its
  clause was loosened.
- Production: allowlist the backup tool's app id if decoys live in a
  backed-up vault; set alert grouping by `Token` so one intrusion is one
  incident.

## Test evidence
Run on 2026-11-07 in the Kusto emulator; details in
[tests/evidence.md](tests/evidence.md). 3 of 3 positive cases matched,
0 of 7 negatives. All samples are hand-written: no recorded honeytoken
or Key Vault audit data was available. The recorded Splunk tenant data
(52 records, incl. 10 service principal sign-ins) returned 0 rows, as
expected (no decoy there); it only shows the query runs on Microsoft's
published schema.

## Blind spots
- Decoys nobody finds. The rule is only as good as where the decoy
  secret is planted (public repo, `.env` in a container image, pipeline
  variable) and how believable it is.
- Key Vault in resource-specific mode (`AZKVAuditLogs`): not read.
- An attacker who validates a found secret in a way that does not reach
  Entra sign-in logs (e.g. only checking its format) is not seen.
- A careful human who recognises a decoy and leaves it alone. Agents
  that try every credential are the case this rule is strongest
  against; that is an inference from Microsoft's description, not a
  measured rate.

## References
- Microsoft, "Threat actors use agentic AI tooling to find and abuse
  exposed secrets", 2026-11-05,
  https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
  (fetched 2026-11-07).
- Microsoft Sentinel Deception (HoneyTokens) solution, Azure-Sentinel
  repo at c0c2dc2 (read with git, 2026-11-07).
- Table columns and types: `schemas/reference/sentinel/`
  (AADServicePrincipalSignInLogs and AzureDiagnostics from Microsoft's
  Azure-Sentinel sample metadata at c0c2dc2).
