# One Entra sign-in session used successfully from two countries

ATT&CK: T1550.001, T1550.004 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If an attacker replays a stolen Entra session cookie or refresh token,
the victim's session (one `SessionId`) will show successful sign-ins
from the victim's location and from the attacker's, and when the
attacker is in another country, from two countries.

## Data sources
- Log source `entra-signin` (owner: identity team): Sentinel
  `SigninLogs` and `AADNonInteractiveUserSignInLogs`. Both are needed:
  replayed cookies and refresh tokens mostly show up as non-interactive
  sign-ins.
- Fields: `SessionId`, `ResultType`, `LocationDetails`, `IPAddress`,
  `AutonomousSystemNumber`, `AppDisplayName`, `UserAgent`,
  `IsInteractive`, `UserPrincipalName`, `TimeGenerated`.
- Tier targeted, not baseline: the tables are native to every tenant
  that exports sign-in logs, so the schema check alone would allow
  baseline, but the false-positive profile (VPNs, travel) depends on the
  customer, and no recorded data with session ids was available to
  measure it. A customer gets it by listing it in `include`.

## Detection logic
Full query in `rule.yaml`. In order:
1. Union of both sign-in tables, each with `LocationDetails` turned into
   text first, because it is dynamic in `SigninLogs` and a string in
   `AADNonInteractiveUserSignInLogs`; a plain union of the two types
   would split the column.
2. Successful sign-ins only (`ResultType == "0"`) with a non-empty
   `SessionId`.
3. Country from `LocationDetails.countryOrRegion`; sign-ins with no
   country are dropped.
4. Summarize per user and `SessionId`: countries, IPs, ASNs, apps, user
   agents, interactive and non-interactive counts, first and last time.
5. Alert when one session has more than one country.
Runs hourly over the last 4 hours, so a session that keeps being used
from two countries can alert in up to four consecutive runs.

## Why this logic
- Alternative 1, two IP addresses in one session: catches a replay from
  the same country (the recorded Splunk replay is AWS to AWS, both US),
  but sessions change IP routinely (Wi-Fi to mobile, IPv4 and IPv6,
  corporate egress). Tested: an IP-based version matches the
  same-country negative.
- Alternative 2, two ASNs in one session: a middle ground; still noisy
  for laptops moving between home and office. A tuning option.
- Alternative 3, per user instead of per session ("impossible travel"):
  two devices in two places are normal for travellers and shared
  accounts, and Entra ID Protection already does it. The session key
  is what makes this a replay signal (tested: a per-user version
  matches the two-sessions negative).
- Alternative 4, Entra ID Protection "Anomalous token" risk events
  (`AADUserRiskEvents`): better where licensed (P2), and not in every
  tenant; this rule needs only the sign-in logs.
- Country difference is what Microsoft's session cookie theft playbook
  checks.

## False positives
- VPN or proxy egress in another country during one session (split
  tunnelling, a corporate VPN in a head-office country).
- A user who crosses a border and keeps the session (train, flight with
  Wi-Fi).
- Wrong or coarse IP geolocation on mobile and satellite networks.
- Sign-ins with an empty `SessionId` are ignored, which removes some
  noise and some true positives.

## Tuning
- Allowlist known VPN egress ranges or ASNs per customer before
  enabling.
- Customers whose users rarely travel can switch step 5 to more than
  one ASN to catch same-country replays (Alternative 2), accepting more
  alerts.
- The 4-hour period with an hourly run re-alerts the same session; a
  customer that wants one alert per session can add alert grouping by
  `SessionId` in Sentinel.

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positive cases | Negatives | Recorded datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 2 of 2 matched (4 events) | 0 of 6 matched | 0 rows from 127 records; **no recorded record has a SessionId**, so this says nothing |

This is the weakest evidence of the identity rules. Both positive cases
are hand-written: copies of recorded records (the Evilginx2 replay, an
interactive sign-in) with a session id added and, for the replayed
record, a different IP and country. The 6 negatives are hand-written
the same way. Each negative was shown to match when the clause it tests
is removed. The recorded sign-ins only show that the query runs on
Microsoft's published schema of both tables.

## Blind spots
- Replay from the victim's own country (residential proxies, local
  VPS): not alerted. The recorded Splunk replay is this case.
- Token theft that starts a new session (device code phishing, a
  refresh token redeemed into a new session), if Entra gives it a new
  `SessionId`.
- Replay against non-Entra applications with their own cookies.
- Sign-ins that Entra does not log with a country, or logs with an
  empty `SessionId`.
- Service principal and managed identity sign-ins (other tables).

## References
- Microsoft, "Alert grading for session cookie theft alert", last
  updated 2026-07-02,
  https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert
  (fetched 2026-10-27).
- Microsoft, "Token theft playbook",
  https://learn.microsoft.com/security/operations/token-theft-playbook
  (fetched 2026-10-27).
- Sentinel `SigninLogs` and `AADNonInteractiveUserSignInLogs` columns and
  types: `schemas/reference/sentinel/`.
