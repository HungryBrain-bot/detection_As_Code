# Password spraying against Okta (T1110.003)

## What the attack is
The same attack as B8 against an Okta org: a few common passwords tried
against many accounts, few attempts per account, so lockout thresholds
are not reached.

## How the attack happens
1. Collect usernames (Okta often uses the email address).
2. Submit username and password to the org's sign-in endpoint (the recorded spray hits `/idp/idx/identify`), one attempt per account per round.
3. Rotate IPs when blocked; repeat with the next password.

## Real-world use
Wiz (2026-10-22): an ARTEX-using actor that overlaps with Storm-0940 would "Password-spray corporate Okta and Entra ID environments"; "The activity was IDP-agnostic". Wiz gives no Okta-specific counts. Microsoft's report covers Entra only. See docs/threats/artex-phase3-identity.md.

## What it leaves in the logs
Okta System Log: `user.session.start` with `outcome.result` FAILURE and `outcome.reason` INVALID_CREDENTIALS (recorded), `user.account.lock` with LOCKED_OUT (recorded), `actor.alternateId` (the username tried), `client.ipAddress`, `client.userAgent.rawUserAgent`. In Sentinel: `OktaSSO` columns with `_s`, `_d`, `_b` suffixes. Requests blocked by ThreatInsight have no username.

## Prerequisites
Usernames and network access to the Okta org.

## Mapping
T1110.003 Password Spraying, tactic credential-access (ATT&CK enterprise bundle, mitre/cti master, fetched 2026-11-07).

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Splunk attack_data, `T1110.003/okta_multiple_users_from_ip`, `T1110/okta_multiple_accounts_lockout` @ b52ee68 (Apache-2.0).
