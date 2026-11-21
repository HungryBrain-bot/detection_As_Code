# Password spray against AWS console and IAM Identity Center sign-ins (T1110.003)

## What the attack is
A password spray: one or a few common passwords tried against many
accounts, few tries per account so lockout and per-account alerts do
not trip. On AWS the targets are IAM users with console passwords, the
root user, and IAM Identity Center users whose password Identity Center
checks.

## How the attack happens
1. The attacker collects user names (an IAM sign-in URL with the account
   id or alias; Identity Center user names are usually email addresses).
2. They submit one password for each name, from one or many addresses,
   in rounds.
3. They come back later with another password for the same names.

## Real-world use
- Microsoft (2026-10-21) and Wiz (2026-10-22) describe ARTEX-linked
  password sprays against Entra ID (B8, docs/threats/artex-phase3-identity.md).
- **No fetched source shows ARTEX spraying AWS console or Identity
  Center sign-ins.** The rule detects the behaviour on AWS; the recorded
  spray it catches is a Splunk lab recording (2022), not ARTEX.

## What it leaves in the logs
`AWSCloudTrail`: `ConsoleLogin` with `ResponseElements`
`{"ConsoleLogin":"Failure"}`, `ErrorMessage` "Failed authentication"
(existing user) or "No username found in supplied account" with the
user name hidden; Identity Center `CredentialChallenge` (user name) and
`CredentialVerification` with `ServiceEventDetails`
`{"CredentialVerification":"Failure"}`; `SourceIpAddress`, `UserAgent`.

## Prerequisites
A multi-region trail that includes us-east-1, in Sentinel.

## Mapping
T1110.003 Brute Force: Password Spraying, as for B8. ID checked with
`python -m dac validate --attack-bundle` on 2026-11-21.

## References
- See README.md, References.
