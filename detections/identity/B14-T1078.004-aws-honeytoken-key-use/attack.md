# Stolen AWS access key or secret tried by an attacker (T1078.004, T1555.006)

## What the attack is
An IAM user's long-term access key pair leaks (public repository,
`.env` file, CI log, container image). Whoever finds it calls AWS with
it. A decoy key planted where real keys leak turns that first call into
an alert, because no one legitimate uses it. The same idea covers a
decoy secret in Secrets Manager or Parameter Store: an attacker inside
the account who lists and reads secrets reads it too.

## How the attack happens
1. The attacker, or an agent searching code hosts for them, finds an
   access key id and secret access key.
2. They check whether it works and whose it is, typically with a cheap
   identity call, then list what they can reach.
3. With a working identity they look for more secrets, in Secrets
   Manager (`GetSecretValue`) and Parameter Store (`GetParameter(s)`).

## Real-world use
- Microsoft (2026-11-05) describes agentic tooling finding secrets on
  GitHub and using them against Entra ID and Key Vault. That report is
  about Azure. **No source fetched for this project describes ARTEX, or
  the same agents, using AWS keys.** This rule targets the same
  behaviour on AWS; whether those actors do it there is not known.

## What it leaves in the logs
`AWSCloudTrail`: `UserIdentityAccessKeyId` (the key used), `UserIdentityArn`,
`EventSource` / `EventName`, `ErrorCode`, `SourceIpAddress`, `UserAgent`,
and for secret reads `RequestParameters` with the secret id or
parameter name.

## Prerequisites
A planted decoy key (an IAM user with no permissions, in an account
whose CloudTrail reaches Sentinel) and/or decoy secrets, listed in
`Honeytoken_CL`.

## Mapping
T1078.004 Valid Accounts: Cloud Accounts (the decoy key is a valid
cloud credential being used); T1555.006 Credentials from Password
Stores: Cloud Secrets Management Stores (reading Secrets Manager / SSM
secrets). Same mapping as B4. IDs checked with `python -m dac validate
--attack-bundle` on 2026-11-21.

## References
- See README.md, References.
