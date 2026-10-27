# Session cookie or token replay against Entra ID (T1550.001, T1550.004)

## What the attack is
After a user signs in and passes MFA, Entra ID gives the browser a
session cookie and gives apps refresh tokens. Whoever holds them is
treated as that signed-in user, MFA included. An attacker who steals
one (with an adversary-in-the-middle phishing proxy, or from the
user's device with an infostealer) imports it into their own browser or
tool and continues the user's session from their own machine, without
the password and without an MFA prompt.

## How the attack happens
1. The attacker sends a phishing link to a reverse proxy (Evilginx2,
   and phishing-as-a-service kits built the same way) that relays the
   real Microsoft sign-in page.
2. The user signs in and completes MFA through the proxy. The proxy
   keeps the session cookie Entra issues (or an infostealer later copies
   cookies and tokens from the browser profile).
3. The attacker imports the cookie into another browser, or redeems the
   refresh token from a script, from their own IP address.
4. Entra sees a sign-in that is already authenticated:
   "MFA requirement satisfied by claim in the token", logged as an
   interactive or (very often) non-interactive sign-in, in the same
   session as the victim's.
5. The attacker reads mail, adds inbox rules, registers an MFA method
   or an OAuth app (B1, B2) to keep access.
6. The recorded Splunk dataset follows these steps: Evilginx2 steals a
   user's session cookie, which is "imported ... into a different
   browser to access Azure AD resources from a different location and
   source ip" (Splunk's dataset description).

## Real-world use
- Microsoft Defender XDR documentation, "Alert grading for session
  cookie theft alert" (last updated 2 July 2026): describes AiTM
  phishing in which "the attacker is able to steal the target's password
  and session cookie", and tells investigators to look at session ID
  information and for "a time difference between sign-in activities
  where there's a difference in the geo-location. Multiple sessions
  shouldn't be possible for the same account with different locations
  (indicating that the session could be stolen)". This rule implements
  that check on the Sentinel sign-in tables.
- Microsoft Threat Intelligence, "Threat actors misuse OAuth
  applications to automate financially driven attacks" (12 December
  2023): an AiTM proxy "allowed them to steal the token from the user's
  session cookie", and "Later, the stolen token was leveraged to perform
  session cookie replay activity".
- No 2025-2026 incident report naming a group was fetched for this
  rule; the dated sources above are Microsoft's current playbook and a
  2023 report.

## What it leaves in the logs
Sentinel `SigninLogs` (interactive) and
`AADNonInteractiveUserSignInLogs` (token refreshes and silent sign-ins):
- `SessionId`: the Entra session the sign-in belongs to. A replayed
  cookie or refresh token continues the victim's session, so the same
  `SessionId` appears from the attacker's IP.
- `IPAddress`, `LocationDetails.countryOrRegion`,
  `AutonomousSystemNumber`: where each sign-in came from. In the
  non-interactive table `LocationDetails` is a JSON string, not a
  dynamic column.
- `ResultType` "0", `AuthenticationDetails` "Previously satisfied",
  `Status.additionalDetails` "MFA requirement satisfied by claim in the
  token", `IncomingTokenType` (for example `primaryRefreshToken`),
  `UniqueTokenIdentifier` (one per issued token, not per session).
- `UserAgent`, `AppDisplayName`: the attacker's browser or tool.
The attacker controls their IP (a residential proxy or VPN in the
victim's country defeats a location check) and their user agent; they
do not control `SessionId`.

## Prerequisites
A stolen session cookie or refresh token for a user whose session is
still valid: an AiTM phishing kit (T1557, after T1566.002) or an
infostealer on the user's device (T1539 Steal Web Session Cookie). No
privileges in the tenant are needed.

## Mapping
- T1550.004 Use Alternate Authentication Material: Web Session Cookie:
  ATT&CK describes importing a stolen cookie "into a browser they
  control", which is the AiTM case and the recorded dataset.
- T1550.001 Application Access Token: replay of a stolen refresh or
  access token from a script appears the same way in these tables.
- Tactic lateral-movement (the only tactic ATT&CK v20.0 gives both).
  The project scope lists T1550.001 for this rule; T1550.004 is added
  because the main real-world case (AiTM cookie theft) is that
  sub-technique, and mapping only .001 would misstate what is covered.
- Not T1539 or T1557: those are the theft, on the user's device or the
  proxy, which Entra logs do not show.

## References
- Microsoft, "Alert grading for session cookie theft alert", Microsoft
  Defender XDR documentation, last updated 2026-07-02,
  https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert
  (fetched 2026-10-27).
- Microsoft Threat Intelligence, "Threat actors misuse OAuth
  applications to automate financially driven attacks", 12 December
  2023,
  https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
  (fetched 2026-10-27).
- Microsoft, "Token theft playbook", last updated 2024-03-07,
  https://learn.microsoft.com/security/operations/token-theft-playbook
  (fetched 2026-10-27).
- MITRE ATT&CK T1550.001 and T1550.004 (STIX bundle v20.0 read
  2026-10-27).
- Splunk attack_data, T1185/azure_ad_concurrent_sessions_from_different_ips
  (Evilginx2, 2023-01-24), commit b52ee68,
  https://github.com/splunk/attack_data (fetched 2026-10-27).
