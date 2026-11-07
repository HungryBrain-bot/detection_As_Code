# Probing legacy authentication and ROPC to get past MFA (T1110.003, T1078.004)

## What the attack is
Protocols such as IMAP, POP, SMTP AUTH, Exchange ActiveSync and EWS, and
the OAuth resource-owner password grant (ROPC), send a username and
password in one request. They cannot show an MFA prompt, so where they
are still allowed they confirm a password, or grant access, without MFA.

## How the attack happens
1. Take accounts and candidate passwords (from a spray or a leak).
2. Try each against legacy endpoints or the token endpoint with `grant_type=password`.
3. Read the answer: success means legacy access; "MFA required" means the password is right, which can be reused on any flow that does not enforce MFA.
Tools: MFASweep, MSOLSpray, o365spray, and plain curl or Python against `login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.

## Real-world use
Neither Wiz's post nor Microsoft's Storm-0940 report mentions legacy authentication, ROPC, Autodiscover or EWS. Wiz says the actor would "probe SSO and Microsoft 365-specific endpoints" without naming them. This rule rests on the general technique; the recorded example is Splunk's MFASweep lab run, not ARTEX. See docs/threats/artex-phase3-identity.md.

## What it leaves in the logs
`SigninLogs`: `ClientAppUsed` with the protocol name (legacy) or `AuthenticationProtocol` "ropc"; `ResultType` 50126 (wrong password), 50076/50079 (MFA required), 0 (success). Recorded MFASweep ROPC attempts: "Mobile Apps and Desktop clients", "ropc", 50076, apps "Azure Active Directory PowerShell" and "Microsoft Azure PowerShell".

## Prerequisites
Legacy authentication or ROPC not blocked for the account (for success); account names and passwords to try.

## Mapping
T1110.003 Password Spraying when tried across accounts; T1078.004 Cloud Accounts when the password is accepted and the account usable. Tactics credential-access, initial-access. Checked against the ATT&CK enterprise bundle (mitre/cti master, fetched 2026-11-07).

## References
- Microsoft Learn, ROPC, https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc (fetched 2026-11-07)
- Splunk attack_data, `T1078/azure_ad_multiple_appids_and_useragents_auth` @ b52ee68 (Apache-2.0).
