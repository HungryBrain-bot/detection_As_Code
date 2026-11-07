# Password spraying against a cloud identity provider (T1110.003)

## What the attack is
The attacker tries one or a few common passwords against many accounts,
instead of many passwords against one, so that no single account reaches
its lockout threshold. Any account with a weak password and no MFA (or a
protocol that skips MFA) gives the attacker a valid sign-in.

## How the attack happens
1. Build a list of accounts (from the company website, LinkedIn, an earlier breach, or by probing which usernames exist).
2. Submit a password to each account through the IdP's sign-in or token endpoint, one attempt per account per round.
3. Wait, rotate source IPs if blocked, and repeat with the next password.
Tools: MSOLSpray, o365spray, TREVORspray, Spray365, and scripted Python or curl clients. The ARTEX reports name curl and Python HTTP clients, not a spray tool.

## Real-world use
Microsoft (2026-10-21): Storm-0940 "conducted an automated cross-tenant password-spray campaign targeting 327 accounts across eight organizations", 151,000+ failures peaking "at 2,900 failures per minute", 48 accounts with over 1,000 failures, lockout responses nearly 98%, and "no successful authentication". Wiz (2026-10-22): an ARTEX-using actor that overlaps with Storm-0940 sprayed "corporate Okta and Entra ID environments", "hundreds of users", with a median gap between attempts of "strictly one second", and rotated IPs "when blocked". See docs/threats/artex-phase3-identity.md.

## What it leaves in the logs
Entra `SigninLogs`: one row per attempt with `UserPrincipalName`, `IPAddress`, `ResultType` 50126 (wrong password) or 50053 (locked or blocked), `ClientAppUsed`, `UserAgent`. Recorded sprays (Splunk attack_data) log as `ClientAppUsed` "Mobile Apps and Desktop clients". The attacker controls IPs, timing, user agent and order; it does not control which accounts fail.

## Prerequisites
A list of account names and network access to the IdP. No credentials.

## Mapping
T1110.003 Password Spraying ("a single or small list of commonly used passwords against many different accounts"; ATT&CK notes adversaries may "target single sign-on (SSO) and cloud-based applications"), tactic credential-access. Not T1110.001 Password Guessing (many passwords, one account; tested as a negative with the recorded brute force). Checked against the ATT&CK enterprise bundle (mitre/cti master, fetched 2026-11-07).

## References
- Microsoft Threat Intelligence, Storm-0940 / ARTEX report, 2026-10-21, https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/ (fetched 2026-11-07)
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- MITRE ATT&CK T1110.003 (bundle fetched 2026-11-07).
