# Self-service password reset run for several users from one network, or several users throttled

ATT&CK: T1589 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
A real user resets their own password. A client that runs self-service
password reset (SSPR) for several different users from one network is
testing which accounts exist and how weak their recovery is; and several
users throttled from SSPR in one hour means someone is hammering it.

## Data sources
- `entra-audit` (identity team): `AuditLogs`, SSPR activities (logged under the "Self-service Password Management" service).
- Okta is not covered: the event that records a self-service reset could not be confirmed, and Microsoft's own hunting query reads `user.account.reset_password` as an admin reset (docs/threats/artex-phase3-identity.md).

## Detection logic
```kql
// B11: SSPR for several users from one network (detections/identity/B11-T1589-recovery-for-many-users/README.md)
    let window = 1h;
    let min_users_per_network = 3;
    let min_blocked_users = 2;
    let sspr_ops = dynamic(["Self-service password reset flow activity progress", "Reset password (self-service)",
        "Unlock user account (self-service)", "Blocked from self-service password reset", "User started password reset"]);
    let net = (ip: string) { iff(ip contains ":", strcat(substring(parse_ipv6(ip), 0, 19), "::/64"), format_ipv4_mask(ip, 24)) };
    let sspr = AuditLogs
    | where OperationName in~ (sspr_ops)
    | extend IPAddress = tostring(InitiatedBy.user.ipAddress),
             Target = tolower(coalesce(tostring(TargetResources[0].userPrincipalName), tostring(InitiatedBy.user.userPrincipalName))),
             Window = bin(TimeGenerated, window);
    let by_network = sspr
    | where isnotempty(IPAddress)
    | extend Network = net(IPAddress)
    | summarize Users = dcount(Target), SampleUsers = make_set(Target, 20), IPAddresses = make_set(IPAddress, 10),
                Operations = make_set(OperationName, 10), Steps = make_set(ResultReason, 10), Completed = countif(OperationName =~ "Reset password (self-service)"),
                FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Network, Window
    | where Users >= min_users_per_network
    | extend Reason = "SSPR for several users from one network";
    let blocked = sspr
    | where OperationName =~ "Blocked from self-service password reset"
    | summarize Users = dcount(Target), SampleUsers = make_set(Target, 20), IPAddresses = make_set(IPAddress, 10),
                Operations = make_set(OperationName, 10), Steps = make_set(ResultReason, 10), Completed = 0,
                FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Window
    | where Users >= min_blocked_users
    | extend Reason = "several users throttled from SSPR", Network = "";
    union by_network, blocked
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, Reason, Network, Window, Users, Completed, SampleUsers, IPAddresses, Operations, Steps, FirstSeen, LastSeen
```
1. SSPR activities: "Self-service password reset flow activity progress", "Reset password (self-service)", "Unlock user account (self-service)", "Blocked from self-service password reset", "User started password reset" (names from Microsoft Learn, case-insensitive).
2. Per source network (IPv4 /24, IPv6 /64 of `InitiatedBy.user.ipAddress`) and hour: alert on at least 3 distinct target users. `Completed` counts finished resets.
3. Separately, per hour from any network: alert on at least 2 users blocked from SSPR.

## Why this logic
- Wiz's playbook for the actor: "Abuse account recovery: Repeatedly invoke password-reset, username-recovery, activation, and reset-token endpoints". Wiz shows it on custom app endpoints and Cognito, not Entra SSPR; this rule covers the Entra flow the draft names.
- Several users from one network: one user retrying their own reset is normal (tested: 6 attempts and a completed reset, no alert).
- Blocked users from anywhere: Microsoft blocks a user after "more than five total times in 24 hours"; two blocked users in an hour does not depend on the attacker's network, so it survives IP rotation.
- "Change password (self-service)" (signed-in user, knows the password) and "Reset password (by admin)" (helpdesk) are not counted (tested).
- Thresholds (3 users, 2 blocked, one hour) are this project's.

## False positives
- A shared office or VPN egress where several users forget passwords on a Monday morning or after a forced password expiry.
- A helpdesk walking users through SSPR from one place.
- Microsoft's Azure-Sentinel rule notes flow progress events can come from a password policy that makes signed-in users rotate passwords; if your tenant does that, exclude those flows by `ResultReason`.

## Tuning
- Negatives tested (7 scenarios): two users from one /24; one user retrying and completing; four users from four networks; one user blocked; four signed-in password changes; four admin resets; two users in one hour and a third in the next. Loosenings that made them match: users per network 3 to 2 (3 rows), 3 to 1 (8), blocked 2 to 1 (1), network grouping removed (1), change and admin reset counted (2).
- Check first that your tenant's SSPR audit records carry `InitiatedBy.user.ipAddress`; if they do not, only the blocked-users branch works.

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). 3 of 3 positive cases matched, 0 of 25 negative events. All samples are hand-written; no recorded SSPR event was available.

## Blind spots
- Recovery abuse on the application's own reset endpoints (Wiz's `GeneratePasswordResetToken`, `/forgot_password`) or Cognito: not in Entra's audit log.
- A slow sweep (under 3 users an hour per network) with rotating networks, unless users get blocked.
- Okta.
- SSPR records with no initiator IP (not verified either way).

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Microsoft Learn, SSPR reporting, https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-reporting (fetched 2026-11-07)
- Azure-Sentinel c0c2dc2, `Detections/MultipleDataSources/MultiplePasswordresetsbyUser.yaml`, `Solutions/Okta Single Sign-On/Hunting Queries/UserPasswordReset.yaml`
- docs/threats/artex-phase3-identity.md; ADR 011.
