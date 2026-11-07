# Many Okta accounts fail with a wrong password, or the same accounts are sprayed again

ATT&CK: T1110.003 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
Same as B8, for Okta: if an attacker sprays passwords at the Okta org,
many accounts fail sign-in with a wrong password or get locked out
without a matching success, whatever IPs the attempts come from, and an
agent that returns fails the same accounts again.

## Data sources
- `okta-system-log` (identity team): `OktaSSO`, written by Sentinel's Okta Single Sign-On connector. The column names are Microsoft's (`eventType_s`, `outcome_reason_s`, `actor_alternateId_s`, `client_ipAddress_s`; reference schema from Azure-Sentinel c0c2dc2). The v2 connector's `OktaV2_CL` uses other names and is not covered.

## Detection logic
```kql
// B9: account-side password spray, Okta (detections/identity/B9-T1110.003-okta-account-side-spray/README.md)
    let round_size = 1h;
    let min_accounts = 15;        // breadth: failing accounts in one round
    let min_spray_round = 10;     // a round with this many failing accounts is a spray round
    let min_retargeted = 5;       // accounts failing in two or more spray rounds
    // Wrong-password reasons as read by the Okta spray rule in Azure-Sentinel; lockouts as recorded.
    let fail_reasons = dynamic(["INVALID_CREDENTIALS", "VERIFICATION_ERROR"]);
    let attempts = OktaSSO
    | where (eventType_s == "user.session.start" and (outcome_result_s == "SUCCESS" or outcome_reason_s in (fail_reasons)))
        or eventType_s == "user.account.lock"
    | where isnotempty(actor_alternateId_s)
    | extend Account = tolower(actor_alternateId_s), IPAddress = client_ipAddress_s,
             Failed = not(eventType_s == "user.session.start" and outcome_result_s == "SUCCESS"),
             Outcome = strcat(eventType_s, ":", outcome_reason_s), UserAgent = client_userAgent_rawUserAgent_s,
             Round = bin(TimeGenerated, round_size);
    // An account counts in a round if it failed and did not also sign in successfully in that round.
    let failing = attempts
    | summarize Failures = countif(Failed), Successes = countif(not(Failed)) by Account, Round
    | where Failures > 0 and Successes == 0
    | project Account, Round;
    let failed = attempts | where Failed | join kind=inner failing on Account, Round;
    let per_ip = failed | summarize IPFailures = count() by Round, IPAddress;
    let breadth = failed
    | summarize FailingAccounts = dcount(Account), Accounts = make_set(Account, 50), Failures = count(),
                DistinctIPs = dcount(IPAddress), Outcomes = make_set(Outcome), UserAgents = make_set(UserAgent, 10),
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
                DistinctIPs = dcount(IPAddress), Outcomes = make_set(Outcome), UserAgents = make_set(UserAgent, 10),
                SprayRounds = dcount(Round), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    | where FailingAccounts >= min_retargeted
    | extend MaxFailuresPerIP = toscalar(retargeted | summarize n = count() by IPAddress | summarize max(n)),
             Reason = "re-targeted", Round = datetime(null);
    union breadth, retarget
    // Distributed: many sources, each with few attempts. Reported, not required.
    | extend Distributed = DistinctIPs >= 10 and MaxFailuresPerIP <= 3
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, Reason, Round, FailingAccounts, SprayRounds, Failures, DistinctIPs, MaxFailuresPerIP,
              Distributed, Outcomes, UserAgents, Accounts, FirstSeen, LastSeen
```
1. Keep `user.session.start` successes, `user.session.start` failures with reason INVALID_CREDENTIALS or VERIFICATION_ERROR, and `user.account.lock`.
2. Steps 2 to 5 are B8's: per account and one-hour round, breadth at 15 accounts, re-targeting at 5 accounts across two spray rounds of 10, IP figures reported only.

## Why this logic
- The same reasoning as B8 (per account, success removes typos, IP count not required). Wiz: the activity "was IDP-agnostic, hitting both Entra and Okta".
- Failure reasons: INVALID_CREDENTIALS and VERIFICATION_ERROR are the two the Okta password-spray rule in Microsoft's Azure-Sentinel repository reads; the recorded Okta spray (Splunk attack_data) has INVALID_CREDENTIALS. Okta's own description of these values could not be read (the event-type page fetch was incomplete); they rest on the recorded data and Microsoft's rule.
- Lockouts: `user.account.lock` with reason LOCKED_OUT is in the recorded Okta lockout set; a spray that trips lockouts is the Okta counterpart of Entra 50053.
- Not per IP: Microsoft's Okta rule alerts on more than 15 users from one IP in 5 minutes, which IP rotation defeats. Run both.
- Thresholds are the same as B8's so the two IdPs are comparable; they are this project's.

## False positives
- As B8: large orgs, a sync tool retrying stale passwords, authorised tests.
- Okta ThreatInsight blocks do not help or hurt: Okta says "Blocked requests aren't treated as failed user sign-in attempts", so they never reach this count.

## Tuning
- Negatives tested (5 scenarios): 25 users mistyping then succeeding; 14 accounts failing in one hour; a second spray-size hour of which only 4 accounts failed earlier; 20 MFA-factor failures (`user.authentication.auth_via_mfa`, not a sign-in); 20 sign-ins denied by policy (a hand-written reason value). Each of four loosenings (success clause removed, 15 to 14, 5 to 4, any `user.*` failure counted) made at least one negative match.

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). 3 of 3 positive cases matched, 0 of 114 negative events. The only recorded Okta data (a 10-account spray and a 7-account lockout from one IP, on different days) returned nothing: both are below the 15-account threshold.

## Blind spots
- Requests ThreatInsight blocks: no username, not counted as failed sign-ins.
- Sprays below 10 accounts an hour (the recorded 10-account spray is one).
- Failure reasons other than the two read here; an Okta org whose sign-in policy reports wrong passwords differently would be missed. Check the reasons in your own `OktaSSO` data before relying on this.
- `OktaV2_CL`.

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Okta ThreatInsight, https://help.okta.com/en-us/content/topics/security/threat-insight/about-threatinsight.htm (fetched 2026-11-07)
- Azure-Sentinel c0c2dc2, `Solutions/Okta Single Sign-On/Analytic Rules/PasswordSpray.yaml` and `.script/tests/KqlvalidationsTests/CustomTables/OktaSSO.json` (read with git, 2026-11-07)
- docs/threats/artex-phase3-identity.md; ADR 011.
