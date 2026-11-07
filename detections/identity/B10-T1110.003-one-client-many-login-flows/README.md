# One client network works through several Entra login flows within 30 minutes

ATT&CK: T1110.003, T1589 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
A real user follows one login flow. An agent working through every flow
the tenant exposes shows, from one source network within half an hour,
more than one of: wrong passwords on several accounts, a legacy-protocol
or ROPC attempt, and password-reset activity for several users.

## Data sources
- `entra-signin` (identity team): `SigninLogs`.
- `entra-audit` (identity team): `AuditLogs`, self-service password reset (SSPR) activities.
- Not read: OAuth callback and JWT rejections (rule B13, `AppAuthEvent_CL`) and Okta. Putting them in would hold this rule back for every customer without those logs, since the gate needs every source a rule reads (ADR 011).

## Detection logic
```kql
// B10: one client network, several login flows (detections/identity/B10-T1110.003-one-client-many-login-flows/README.md)
    let window = 30m;
    let min_failed_accounts = 3;
    let min_recovery_users = 2;
    let min_behaviours = 2;
    let fail_codes = dynamic(["50126", "50053"]);
    // Client app names that Microsoft Sentinel content (Azure-Sentinel c0c2dc2) treats as legacy, compared case-insensitively.
    let legacy_clients = dynamic(["Authenticated SMTP", "SMTP Auth", "AutoDiscover", "Exchange ActiveSync", "Exchange Online PowerShell",
        "Exchange Web Services", "IMAP4", "MAPI Over HTTP", "Offline Address Book", "Outlook Anywhere (RPC over HTTP)",
        "Outlook Service", "POP3", "Reporting Web Services", "Other clients"]);
    let sspr_ops = dynamic(["Self-service password reset flow activity progress", "Reset password (self-service)",
        "Unlock user account (self-service)", "Blocked from self-service password reset", "User started password reset"]);
    // Source network: IPv4 /24, IPv6 /64.
    let net = (ip: string) { iff(ip contains ":", strcat(substring(parse_ipv6(ip), 0, 19), "::/64"), format_ipv4_mask(ip, 24)) };
    let signins = SigninLogs
    | where isnotempty(IPAddress)
    | extend Network = net(IPAddress), Window = bin(TimeGenerated, window), Account = tolower(UserPrincipalName);
    let failed = signins
    | where ResultType in (fail_codes)
    | summarize Accounts = dcount(Account), Sample = make_set(Account, 10), IPs = make_set(IPAddress, 10),
                UserAgents = make_set(UserAgent, 5), First = min(TimeGenerated), Last = max(TimeGenerated) by Network, Window
    | where Accounts >= min_failed_accounts
    | extend Behaviour = "failed sign-ins on several accounts";
    let legacy = signins
    | where ClientAppUsed in~ (legacy_clients) or AuthenticationProtocol =~ "ropc"
    | summarize Accounts = dcount(Account), Sample = make_set(Account, 10), IPs = make_set(IPAddress, 10),
                UserAgents = make_set(UserAgent, 5), First = min(TimeGenerated), Last = max(TimeGenerated) by Network, Window
    | extend Behaviour = "legacy protocol or ROPC sign-in";
    let recovery = AuditLogs
    | where OperationName in~ (sspr_ops)
    | extend IPAddress = tostring(InitiatedBy.user.ipAddress), Target = tolower(tostring(TargetResources[0].userPrincipalName))
    | where isnotempty(IPAddress)
    | extend Network = net(IPAddress), Window = bin(TimeGenerated, window)
    | summarize Accounts = dcount(Target), Sample = make_set(Target, 10), IPs = make_set(IPAddress, 10),
                UserAgents = dynamic([]), First = min(TimeGenerated), Last = max(TimeGenerated) by Network, Window
    | where Accounts >= min_recovery_users
    | extend Behaviour = "password reset for several users";
    union failed, legacy, recovery
    | summarize Behaviours = make_set(Behaviour), BehaviourCount = dcount(Behaviour), AccountsPerBehaviour = make_bag(bag_pack(Behaviour, Accounts)),
                SampleAccounts = make_set(Sample, 20), IPAddresses = make_set(IPs, 20), UserAgents = make_set(UserAgents, 10),
                FirstSeen = min(First), LastSeen = max(Last) by Network, Window
    | where BehaviourCount >= min_behaviours
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, Network, Window, BehaviourCount, Behaviours, AccountsPerBehaviour, IPAddresses, SampleAccounts, UserAgents, FirstSeen, LastSeen
```
1. Source network: IPv4 /24 or IPv6 /64 of the sign-in IP or the SSPR initiator IP; 30-minute fixed windows.
2. Behaviour "failed sign-ins on several accounts": 50126 or 50053 on at least 3 accounts.
3. Behaviour "legacy protocol or ROPC sign-in": any attempt with a legacy `ClientAppUsed` (the list in Microsoft's Sentinel content) or `AuthenticationProtocol` "ropc", any result.
4. Behaviour "password reset for several users": SSPR activity (flow progress, reset, unlock, blocked, user started reset) for at least 2 users.
5. Alert when one network shows at least 2 behaviours in one window.

## Why this logic
- Wiz describes the agent trying sign-in, OAuth callbacks, JWTs, SSO routes and account recovery against the same targets, switching "to a different endpoint on the same host" when rate-limited. The 30-minute window is the draft's.
- Network, not IP or user agent: Wiz reports the agent would "Rotate IP addresses when blocked, and constantly circulate user agents"; three of Wiz's five IOC addresses share one /24. The network is the only key that sign-in and audit logs share. /24 and /64 are this project's choice.
- Legacy attempts count at any result, failures and SSPR need several accounts: one failed sign-in or one reset is a normal user; one IMAP or ROPC attempt from a network that is also spraying is not.
- "Change password (self-service)" is not a recovery operation (the user knows the password and is signed in) and is not counted (tested).
- Alternative, Okta in the same rule: needs `OktaSSO` in every customer; one rule per IdP is the pattern (B8/B9). An Okta version is parked.

## False positives
- Shared egress: an office NAT, VPN concentrator or proxy puts many users in one /24. Three users mistyping plus one old mail client using IMAP is two behaviours. Exclude known egress ranges per customer.
- A helpdesk walking several users through SSPR from one office while users there mistype passwords.
- Authorised identity testing.

## Tuning
- Negatives tested (7 scenarios): a spray alone; a POP3 mail client alone; two failing accounts plus IMAP4; one user failing five times then resetting; failures and SSPR from different /24s; failures and SSPR in adjacent windows; failures plus "Change password (self-service)" for three users. Loosenings that made them match: 2 behaviours to 1 (8 rows); failed accounts 3 to 1 with reset users 2 to 1 (2); network grouping removed (1); window 30 minutes to 1 hour (1); change-password counted as recovery (1).

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). 4 of 4 positive cases matched (including one over IPv6), 0 of 40 negative events. All samples are hand-written; no recorded set has more than one of the behaviours from one network, and none has SSPR activity.

## Blind spots
- An agent that uses a different network for each flow.
- Windows are fixed 30-minute bins: behaviours split across a boundary are not combined (tested).
- SSPR records without an initiator IP (whether Entra fills `InitiatedBy.user.ipAddress` for SSPR is not verified).
- Requests to `/autodiscover`, `/EWS` or SSO routes that never authenticate do not reach `SigninLogs`.
- ROPC through the v1 token endpoint, if it logs as protocol "none" (the recorded MSOLSpray sprays log as "Mobile Apps and Desktop clients" with "none"; which endpoint they used is not stated in the dataset).

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Microsoft Learn, SSPR reporting, https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-reporting ; SigninLogs table reference (fetched 2026-11-07)
- Azure-Sentinel c0c2dc2, legacy client lists in `Hunting Queries/SigninLogs/PrivilegedAccountsUsingLegacyAuthentication.yaml` and `Solutions/Business Email Compromise - Financial Fraud/Hunting Queries/LegacyAuthAttempt.yaml`
- docs/threats/artex-phase3-identity.md; ADR 011.
