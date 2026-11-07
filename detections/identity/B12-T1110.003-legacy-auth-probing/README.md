# Legacy-protocol or ROPC sign-ins tried on several accounts, or a password accepted over them

ATT&CK: T1110.003, T1078.004 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
Legacy protocols and the ROPC grant take a password with no interactive
MFA. If someone is probing them, one network tries them against several
accounts in an hour, or one of the attempts gets a password accepted.

## Data sources
- `entra-signin` (identity team): `SigninLogs`.

## Detection logic
```kql
// B12: legacy auth / ROPC probing (detections/identity/B12-T1110.003-legacy-auth-probing/README.md)
    let window = 1h;
    let min_accounts = 3;
    // Password accepted: success, or MFA required / MFA registration required after the password step.
    let password_accepted = dynamic(["0", "50076", "50079"]);
    // Client app names that Microsoft Sentinel content (Azure-Sentinel c0c2dc2) treats as legacy, compared case-insensitively.
    let legacy_clients = dynamic(["Authenticated SMTP", "SMTP Auth", "AutoDiscover", "Exchange ActiveSync", "Exchange Online PowerShell",
        "Exchange Web Services", "IMAP4", "MAPI Over HTTP", "Offline Address Book", "Outlook Anywhere (RPC over HTTP)",
        "Outlook Service", "POP3", "Reporting Web Services", "Other clients"]);
    // Per customer: accounts that are allowed to use a legacy protocol (e.g. the SMTP relay account of a scanner). Empty by default.
    let allowed_legacy_accounts = dynamic([]);
    let net = (ip: string) { iff(ip contains ":", strcat(substring(parse_ipv6(ip), 0, 19), "::/64"), format_ipv4_mask(ip, 24)) };
    SigninLogs
    | where ClientAppUsed in~ (legacy_clients) or AuthenticationProtocol =~ "ropc"
    | where isnotempty(IPAddress)
    | extend Account = tolower(UserPrincipalName)
    | where not(Account in (allowed_legacy_accounts))
    | extend Network = net(IPAddress), Window = bin(TimeGenerated, window),
             Channel = iff(AuthenticationProtocol =~ "ropc", "ROPC", ClientAppUsed)
    | summarize Attempts = count(), Accounts = dcount(Account), SampleAccounts = make_set(Account, 20),
                AcceptedAccounts = make_set_if(Account, ResultType in (password_accepted), 20),
                Channels = make_set(Channel, 10), ResultTypes = make_set(ResultType, 10), Apps = make_set(AppDisplayName, 10),
                IPAddresses = make_set(IPAddress, 10), UserAgents = make_set(UserAgent, 10),
                FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Network, Window
    | where Accounts >= min_accounts or array_length(AcceptedAccounts) > 0
    | extend Reason = iff(array_length(AcceptedAccounts) > 0, "password accepted over legacy or ROPC", "legacy or ROPC tried on several accounts")
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, Reason, Network, Window, Accounts, Attempts, AcceptedAccounts, Channels, ResultTypes, Apps, SampleAccounts, IPAddresses, UserAgents, FirstSeen, LastSeen
```
1. Keep sign-ins whose `ClientAppUsed` is a legacy client (the union of the two lists in Microsoft's Sentinel content, case-insensitive) or whose `AuthenticationProtocol` is "ropc".
2. Drop accounts on the per-customer `allowed_legacy_accounts` list (empty by default).
3. Per source network (IPv4 /24, IPv6 /64) and hour: alert on 3 or more accounts, or on any attempt with ResultType 0, 50076 or 50079 (password accepted: success, or MFA asked for after the password).

## Why this logic
- Microsoft: modern clients show as "browser" or "modern mobile/desktop client"; "If it has a specific client or protocol name, such as "Exchange ActiveSync," it's using legacy authentication." Microsoft publishes no full list, so the rule uses the lists in Microsoft's own Sentinel content.
- ROPC is read from `AuthenticationProtocol` ("none, oAuth2, ropc, wsFederation, saml20, deviceCode", SigninLogs reference): the recorded MFASweep ROPC sign-ins have `ClientAppUsed` "Mobile Apps and Desktop clients", which a `ClientAppUsed` filter alone misses. Microsoft: "Microsoft recommends you do *not* use the ROPC flow; it's incompatible with multifactor authentication (MFA)."
- Password accepted: 50076 is "Due to a configuration change made by the admin such as a Conditional Access policy" multifactor authentication is required; that Entra checked the password first is an inference, though it is how MFASweep-style tools use it. A success (0) over a legacy protocol means legacy authentication is not blocked for that account.
- Several accounts per network, not one: one old mail client on one account is common.
- Thresholds (3 accounts, one hour) are this project's.

## False positives
- Tenants that still allow legacy authentication: every successful IMAP/SMTP/EAS sign-in alerts. Put known accounts in `allowed_legacy_accounts`, or block legacy authentication (which is the point).
- Multifunction printers and scanners sending mail over authenticated SMTP from one office network with several accounts.
- Older Exchange ActiveSync phones on a shared network.

## Tuning
- Negatives tested (5 scenarios): IMAP4 failures on two accounts; six Browser failures; six modern desktop successes; POP3 failures on three accounts from three networks; Exchange ActiveSync lockouts (50053) on three accounts over two hours. Loosenings that made them match: 3 accounts to 2 (2 rows), any client counted (2), network grouping removed (1), 50053 counted as accepted (2).
- Before enabling, list the legacy sign-ins of the last 30 days and fill `allowed_legacy_accounts`.

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). 4 of 4 positive cases matched, 0 of 20 negative events. On recorded data: 1 row, the four MFASweep ROPC attempts on one account answered 50076.

## Blind spots
- Requests to `/autodiscover`, `/EWS` or other endpoints that never reach Entra authentication are not in `SigninLogs`.
- Sprays that log as a modern client: both recorded sprays (MSOLSpray) log as "Mobile Apps and Desktop clients" with protocol "none" and are not seen here (B8 sees them).
- Legacy client names not on either Microsoft list.
- A slow probe under 3 accounts per network per hour whose passwords are all wrong.

## References
- Microsoft Learn: SigninLogs table reference; legacy-authentication workbook; ROPC (https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc); Conditional Access client apps (fetched 2026-11-07)
- Azure-Sentinel c0c2dc2, `Hunting Queries/SigninLogs/PrivilegedAccountsUsingLegacyAuthentication.yaml`, `Solutions/Business Email Compromise - Financial Fraud/Hunting Queries/LegacyAuthAttempt.yaml`
- docs/threats/artex-phase3-identity.md; ADR 011.
