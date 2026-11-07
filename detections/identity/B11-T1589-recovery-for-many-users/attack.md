# Account-recovery abuse to enumerate and take over accounts (T1589)

## What the attack is
The attacker uses the "forgot my password" flow instead of the sign-in
page. The flow's answers can reveal whether an account exists and which
recovery methods it has, and a weak flow (guessable answers, a code sent
somewhere the attacker controls, no rate limit) hands over the account.

## How the attack happens
1. Submit usernames to the recovery flow and compare the responses (exists, does not exist, which methods).
2. For accounts with a weak method, try to complete recovery: guess answers, request codes repeatedly, or target accounts whose recovery contact is stale.
3. Repeat across many users, rotating IPs when throttled.

## Real-world use
Wiz (2026-10-22): the actor's playbook included "Abuse account recovery: Repeatedly invoke password-reset, username-recovery, activation, and reset-token endpoints"; logged `POST /api/v1/Users/GeneratePasswordResetToken → 204` and `POST /forgot_password` on application endpoints, and `ForgotPassword` in AWS Cognito. No fetched source shows the actor using Entra SSPR or Okta recovery. See docs/threats/artex-phase3-identity.md.

## What it leaves in the logs
Entra `AuditLogs`: "Self-service password reset flow activity progress" (with the step in `ResultReason`), "Reset password (self-service)", "Blocked from self-service password reset" (more than five attempts in 24 hours), "Unlock user account (self-service)"; target user in `TargetResources`, initiator in `InitiatedBy`. App endpoints log only where the app logs them.

## Prerequisites
SSPR enabled for the targeted users, and their usernames.

## Mapping
T1589 Gather Victim Identity Information: ATT&CK says identity details may be gathered by "probing and analyzing responses from authentication services that may reveal valid usernames in a system or permitted MFA /methods", and cites "Obsidian SSPR Abuse 2023". Tactic reconnaissance. A completed takeover through recovery has no exact ATT&CK technique; the account is then T1078.004 when used. Checked against the ATT&CK enterprise bundle (mitre/cti master, fetched 2026-11-07).

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Microsoft Learn, SSPR reporting (fetched 2026-11-07)
- MITRE ATT&CK T1589 (bundle fetched 2026-11-07).
