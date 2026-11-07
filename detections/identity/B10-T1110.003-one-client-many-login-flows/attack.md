# One client working through every login flow (T1110.003, T1589)

## What the attack is
Instead of one technique, the attacker runs several against the same
identity provider in quick succession: password guesses on many accounts,
legacy protocols that skip MFA, password-reset requests that reveal
which accounts exist or how they recover, and tampered OAuth or token
requests. Each alone is common; together, from one client, they are a
tool working down a checklist.

## How the attack happens
1. Spray a password across the user list.
2. Try the same accounts over a protocol without interactive MFA (IMAP, POP, SMTP, EAS, EWS, ROPC).
3. Start password reset or account recovery for several users to see which exist and what the flow asks for.
4. Send forged or tampered tokens and OAuth callbacks to the apps (rule B13).
5. When an endpoint rate-limits, move to another on the same host.

## Real-world use
Wiz (2026-10-22), for an ARTEX-using actor overlapping with Storm-0940: "Repeatedly initiate sign-in flows, manipulate OAuth callbacks and state parameters, test unsigned JWTs, and probe SSO and Microsoft 365-specific endpoints"; "Password-spray corporate Okta and Entra ID environments"; "Abuse account recovery: Repeatedly invoke password-reset, username-recovery, activation, and reset-token endpoints"; "When a login page started rate-limiting the activity, the agent simply switched to a different endpoint on the same host and carried on." Wiz does not say these came from one IP range within 30 minutes; that combination is the draft's hypothesis. See docs/threats/artex-phase3-identity.md.

## What it leaves in the logs
`SigninLogs`: failures (50126, 50053) on several accounts; rows with a legacy `ClientAppUsed` or `AuthenticationProtocol` "ropc". `AuditLogs`: SSPR activities ("Self-service password reset flow activity progress", "Blocked from self-service password reset", ...), with the initiator in `InitiatedBy`. The attacker controls IPs and user agents; it is harder to change networks for every flow.

## Prerequisites
A user list and network access to the IdP; SSPR enabled for the users.

## Mapping
T1110.003 Password Spraying (the failure and legacy legs) and T1589 Gather Victim Identity Information ("probing and analyzing responses from authentication services that may reveal valid usernames"; ATT&CK cites an SSPR-abuse write-up), tactics credential-access and reconnaissance. Checked against the ATT&CK enterprise bundle (mitre/cti master, fetched 2026-11-07).

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- MITRE ATT&CK T1110.003, T1589 (bundle fetched 2026-11-07).
