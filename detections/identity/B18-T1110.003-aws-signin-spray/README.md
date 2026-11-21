# Many AWS sign-in accounts fail with a wrong password, or the same accounts are sprayed again

ATT&CK: T1110.003 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

AWS port of [B8](../B8-T1110.003-entra-account-side-spray/) (ADR 014).
Same counting, same thresholds; the sign-ins are AWS console sign-ins of
IAM users and root, and IAM Identity Center password checks.

## Hypothesis
A password spray tries one or a few passwords against many accounts,
often from rotating addresses. Counted from the account side (how many
distinct accounts fail without a success in an hour, and whether the
same accounts come back in a later spray hour), it shows up whatever
the attacker does with source addresses. On AWS, people type passwords
in two places CloudTrail records: the console sign-in of an IAM user or
root (`ConsoleLogin`) and the IAM Identity Center sign-in
(`CredentialVerification`) when Identity Center holds the password
(its own directory, or AWS Managed Microsoft AD).

## Data sources
- `aws-cloudtrail` (cloud platform team): `AWSCloudTrail`. Sign-in
  events are written in a region that depends on the endpoint (AWS:
  IAM users on the global endpoint are recorded in us-east-1; regional
  endpoints in that region), so the trail must cover all regions.
- Identity Center with an external IdP (Entra, Okta) is not covered
  here: the password is checked by the IdP, whose sign-in log is B8 or
  B9.

## Detection logic
Query in [rule.yaml](rule.yaml).
1. Console: `ConsoleLogin` events, result from
   `responseElements.ConsoleLogin` (`Success` / `Failure`). Account =
   account id + IAM user name (lower case), or account id + `root`.
   Failures for a user name AWS replaced with
   `HIDDEN_DUE_TO_SECURITY_REASONS` are dropped.
2. Identity Center: `CredentialVerification` events with
   `CredentialType` `PASSWORD`, result from
   `serviceEventDetails.CredentialVerification`; the user name comes
   from the `CredentialChallenge` with the same `AuthWorkflowID`
   (Identity Center writes `UserName` there, not on the verification).
   Account = `identity-center/` + user name.
3. From here on as B8: per one-hour round, an account counts as failing
   if it failed and had no success in that round. Breadth: 15 or more
   failing accounts in a round. Re-targeted: 5 or more accounts failing
   in two or more rounds that each had 10 or more failing accounts.
4. Addresses and failures per address, surfaces (console /
   identity-center), error messages and user agents are reported, not
   required.

## Why this logic
- Per account, not per address, for B8's reason: the ARTEX material
  describes rotating addresses when blocked (B8 README). The recorded
  spray here came from one address and is caught either way.
- One rule for both surfaces: both are CloudTrail, one log source the
  gate confirms once, and a spray across console and Identity Center
  users is one spray. The mixed positive (8 + 8 accounts) alerts only
  because they are counted together.
- Hidden user names dropped: AWS writes the same string for every
  unknown name, so they cannot be counted as distinct accounts, and
  counting them as one adds nothing. This is the counterpart of B8 not
  counting 50034 (unknown account).
- Thresholds are B8's (15, 10, 5, one hour, six hours); no source gives
  AWS numbers. The recorded spray hit 31 accounts in 80 seconds.
- Success in the round excludes the user who mistypes and signs in
  (25 such users, no alert; removing the clause made it alert).

## False positives
- An outage or a password-policy change that makes many users fail
  without succeeding in the hour. Few organisations have 15 IAM users
  signing in to the console in an hour; where they do, raise
  `min_accounts`.
- An authorised password audit: exclude by address or time window.
- A script retrying stale passwords for many IAM users (rare: scripts
  use access keys, not console passwords).

## Tuning
- Negatives tested (6): 25 users fail then succeed; 14 accounts fail
  in an hour; 20 failures for hidden (unknown) user names; two spray
  hours of 12 accounts with 4 in both; 6 users failing in three
  consecutive hours; 16 Identity Center sign-ins that succeed. Four
  loosenings made a negative match (success clause removed; 15 to 14;
  5 to 4; spray round 10 to 6). Two clauses were not shown to bite on
  the samples: keeping hidden names (the 20 hidden failures are one
  account, under every threshold) and dropping the `PASSWORD` filter
  (no sample has another credential type).
- Production: count accounts failing without success per hour for two
  weeks and set `min_accounts` above the peak.

## Test evidence
Run on 2026-11-21 in the Kusto emulator; [tests/evidence.md](tests/evidence.md).
3 of 3 hand-written positive cases matched, 0 of 6 negative cases. On
74 recorded CloudTrail sign-in events (Splunk attack_data, four sets)
the rule returned 1 row: the recorded spray, 31 IAM users failing from
one address. The other three sets (unknown user names, a few failures
from four addresses, root sign-ins) returned nothing.

## Blind spots
- Sprays with a list of user names that do not exist: AWS hides them,
  and they are not counted. A recorded set of 27 hidden failures from
  one address returned nothing. If that matters, add a per-address
  count of hidden failures (parked, BUILD_LOG.md).
- Identity Center: the field layout comes from AWS's example events
  (fetched); no recorded Identity Center event was available. AWS's
  text puts `CredentialType` under `userIdentity.additionalEventData`
  while its example puts it in `additionalEventData`; the rule reads
  the example's place. If the real event differs, the Identity Center
  half returns nothing.
- An Identity Center sign-in that fails on the user name (no
  `CredentialChallenge` with a `UserName`) is not counted.
- Sign-ins with an external IdP, and Amazon Cognito user pools (their
  CloudTrail events record the user's `sub`, not the user name, and the
  failure shape of `InitiateAuth` was not found in AWS's pages; see
  ADR 014).
- A spray slower than 10 accounts an hour, rounds split across an hour
  boundary (as B8).
- Trails that do not cover us-east-1, where most console sign-ins land.

## References
- AWS, "AWS Management Console sign-in events" (ConsoleLogin failure
  example, `"errorMessage": "Failed authentication"`,
  `"responseElements": {"ConsoleLogin": "Failure"}`; region rules),
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
- AWS, "Understanding IAM Identity Center sign-in events" and "Sign-in
  events examples" (`CredentialChallenge`, `CredentialVerification`,
  `serviceEventDetails` `"CredentialVerification":"Failure"`,
  `AuthWorkflowID`), https://docs.aws.amazon.com/singlesignon/latest/userguide/understanding-sign-in-events.html
- AWS, "Username in sign-in CloudTrail events" ("The `UserName` field
  contains the string `HIDDEN_DUE_TO_SECURITY_REASONS` when the recorded
  event is a console sign-in failure caused by incorrect user name
  input."), https://docs.aws.amazon.com/singlesignon/latest/userguide/username-sign-in-cloudtrail-events.html
- Splunk attack_data b52ee68, the four datasets in tests/datasets.yaml
  (Apache-2.0): recorded `errorMessage` values "Failed authentication"
  and "No username found in supplied account".
- B8 and its references (Wiz 2026-10-22, Microsoft 2026-10-21).
AWS pages fetched 2026-11-21 through a fetch tool.
