# Many Entra accounts fail with a wrong password, or the same accounts are sprayed again

ATT&CK: T1110.003 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If an attacker sprays passwords at the tenant, many accounts fail with a
wrong password (or are locked out) without a matching success, whatever
source IPs the attempts come from; and an agent that comes back for more
rounds fails the same accounts again.

## Data sources
- `entra-signin` (identity team): `SigninLogs` (interactive sign-ins). Non-interactive sign-ins are not read: a spray submits passwords, which is interactive or ROPC, and both land in `SigninLogs`.

## Detection logic
```kql
// B8: account-side password spray, Entra (detections/identity/B8-T1110.003-entra-account-side-spray/README.md)
    let round_size = 1h;
    let min_accounts = 15;        // breadth: failing accounts in one round
    let min_spray_round = 10;     // a round with this many failing accounts is a spray round
    let min_retargeted = 5;       // accounts failing in two or more spray rounds
    let fail_codes = dynamic(["50126", "50053"]);
    let attempts = SigninLogs
    | where ResultType in (fail_codes) or ResultType == "0"
    | where isnotempty(UserPrincipalName)
    | extend Account = tolower(UserPrincipalName), Failed = ResultType != "0", Round = bin(TimeGenerated, round_size);
    // An account counts in a round if it failed and did not also sign in successfully in that round.
    let failing = attempts
    | summarize Failures = countif(Failed), Successes = countif(not(Failed)) by Account, Round
    | where Failures > 0 and Successes == 0
    | project Account, Round;
    let failed = attempts | where Failed | join kind=inner failing on Account, Round;
    let per_ip = failed | summarize IPFailures = count() by Round, IPAddress;
    let breadth = failed
    | summarize FailingAccounts = dcount(Account), Accounts = make_set(Account, 50), Failures = count(),
                DistinctIPs = dcount(IPAddress), ErrorCodes = make_set(ResultType), ClientApps = make_set(ClientAppUsed, 10),
                FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by Round
    | where FailingAccounts >= min_accounts
    | join kind=inner (per_ip | summarize MaxFailuresPerIP = max(IPFailures) by Round) on Round
    | extend Reason = "breadth", SprayRounds = 1;
    let spray_rounds = failing | summarize RoundAccounts = dcount(Account) by Round | where RoundAccounts >= min_spray_round;
    let retargeted_accounts = failing
    | join kind=inner spray_rounds on Round
    | summarize SprayRounds = dcount(Round) by Account
    | where SprayRounds >= 2;
    let retargeted = failed | join kind=inner retargeted_accounts on Account;
    let retarget = retargeted
    | summarize FailingAccounts = dcount(Account), Accounts = make_set(Account, 50), Failures = count(),
                DistinctIPs = dcount(IPAddress), ErrorCodes = make_set(ResultType), ClientApps = make_set(ClientAppUsed, 10),
                SprayRounds = dcount(Round), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    | where FailingAccounts >= min_retargeted
    | extend MaxFailuresPerIP = toscalar(retargeted | summarize n = count() by IPAddress | summarize max(n)),
             Reason = "re-targeted", Round = datetime(null);
    union breadth, retarget
    // Distributed: many sources, each with few attempts. Reported, not required.
    | extend Distributed = DistinctIPs >= 10 and MaxFailuresPerIP <= 3
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, Reason, Round, FailingAccounts, SprayRounds, Failures, DistinctIPs, MaxFailuresPerIP,
              Distributed, ErrorCodes, ClientApps, Accounts, FirstSeen, LastSeen
```
1. Keep wrong-password and lockout failures (50126, 50053) and successes (0).
2. Per account and one-hour round: the account counts if it failed and did not succeed in that round.
3. Breadth: a round with at least 15 such accounts gives one row.
4. Re-targeting: rounds with at least 10 such accounts are spray rounds; at least 5 accounts that failed in two or more spray rounds give one row.
5. Each row reports the distinct IPs, the most failures from one IP and `Distributed` (10 or more IPs, at most 3 failures each). They are not conditions.

## Why this logic
- Per account, not per IP: the owner's point, and the one rotation cannot defeat. Wiz: the agent would "Rotate IP addresses when blocked".
- IP count not required: Microsoft's documented spray came from "Storm-0940 infrastructure at 144.172.64[.]99", 151,000+ failures, so a "many IPs, few attempts each" condition would have missed the one spray with published numbers. The recorded one-IP spray (Splunk attack_data) is caught for the same reason.
- 50126 and 50053: Microsoft Learn defines 50126 as invalid username or password and 50053 as locked out (or blocked for a malicious IP); Microsoft reports lockout responses as "nearly 98%" of Storm-0940's spray.
- No success in the round: a user who mistypes and then signs in is not counted (tested: 25 such users in one hour, no alert). Microsoft: "Expect to see some number of these errors in your logs due to users making mistakes."
- Re-targeting tied to spray rounds: an account failing in two hours on its own is a forgetful user; counting only rounds that were themselves spray-sized keeps that out (tested: 6 users failing in three hours, no alert).
- Thresholds (15, 10, 5, one hour, six hours) are this project's; no source gives accounts per hour. Wiz: bursts of "20 to 60 minutes" and "more than a dozen login attempts" for some users.
- Alternative, a baseline of failing accounts per hour per tenant: better for large tenants, needs 14 days of data the harness does not have; parked as tuning.

## False positives
- Large tenants: 15 users failing without success in an hour can be normal after a password-policy change or an outage. Raise `min_accounts`, or exclude a known event window.
- A misconfigured app or service retrying stale passwords for many accounts (a sync tool after a password change).
- An authorised spray test: exclude by IP or time window.

## Tuning
- Negatives tested (6 scenarios): 25 users mistyping then succeeding; 14 accounts failing in one hour; a second spray-size hour where only 4 accounts were also in the first; 20 accounts failing with 50034 (unknown account); 20 with 50076 (MFA required); 6 users failing in three consecutive hours. Each of five loosenings (success clause removed, 15 to 14, 5 to 4, 50034/50076 counted, spray round 10 to 6) made at least one negative match.
- Production: measure the hourly count of accounts failing without success for two weeks and set `min_accounts` above its peak.

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). 3 of 3 positive cases matched, 0 of 132 negative events. On recorded data: both recorded sprays caught (distributed, 31 accounts from 30 IPs; one IP, 31 accounts), the one-account brute force not.

## Blind spots
- A spray slower than 10 accounts an hour, or one that stops after one round below 15.
- Sprays with a user list of accounts that do not exist (50034), and sign-ins blocked by Conditional Access before the password check.
- A correct guess: that account had a success in the round and is not counted. The other accounts still are. A spray that is caught and then succeeds needs a follow-up hunt for successes from the same IPs.
- Okta (B9) and non-interactive sign-ins.
- Rounds are fixed hours; a spray split across an hour boundary counts half in each.

## References
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Microsoft Threat Intelligence, Storm-0940 / ARTEX report, 2026-10-21, https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/ (fetched 2026-11-07)
- Microsoft Learn, Entra error codes, https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes (fetched 2026-11-07)
- docs/threats/artex-phase3-identity.md (claims checked); ADR 011.
