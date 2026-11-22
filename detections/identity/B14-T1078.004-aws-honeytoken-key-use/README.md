# Honeytoken AWS access key used, or decoy Secrets Manager / Parameter Store secret read

ATT&CK: T1078.004, T1555.006 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

AWS port of [B4](../B4-T1078.004-honeytoken-credential-use/) (ADR 013).

## Hypothesis
If an attacker (or an agent working for one) finds a planted decoy IAM
access key and tries it, CloudTrail records the call with the decoy's
access key id in `userIdentity.accessKeyId`. If they reach Secrets
Manager or Parameter Store with any identity, CloudTrail records the
decoy secret's name in the request. No legitimate process uses either,
so one event is enough to alert.

## Data sources
- `aws-cloudtrail` (cloud platform team): `AWSCloudTrail`, through the
  Sentinel AWS S3 connector. The account that owns the decoy user must
  be in the trail that feeds Sentinel.
- `honeytoken-registry` (detection team): `Honeytoken_CL` (ADR 009),
  with two new `TokenType` values: `AwsAccessKeyId` and `AwsSecretName`
  (secret or parameter name, no ARN, no leading `/`). Re-sent at least
  hourly; if it is not, the rule matches nothing (fails silent).
- Tier targeted: only useful where decoys are planted.

## Detection logic
1. Read the registry; lower-case every value and strip a leading `/`.
2. Key use: any `AWSCloudTrail` row whose `UserIdentityAccessKeyId` is a
   decoy key, whatever the result. The decoy user should have no
   permissions, so most calls will be `AccessDenied`; they still count.
3. Secret named: any Secrets Manager or SSM event whose request names a
   decoy, from `requestParameters.secretId`, `.name` or `.names[]`. An
   ARN is cut down to the name (Secrets Manager: the part after
   `:secret:` minus the `-XXXXXX` suffix; SSM: the part after
   `:parameter`). Exact match only.
4. One row per decoy and surface, with operations, error codes, IPs,
   user agents, the caller ARNs, access key ids and accounts, and the
   planted location from the registry.

## Why this logic
- Exact name match: a real secret `prod/payments/db-admin-v2` must not
  alert. Loosening the match to `has_any` made two negatives match.
- Restricted to Secrets Manager and SSM: the decoy name appearing as a
  value in another service's request (a CodeBuild project list in the
  negatives) is not a read of the secret. Removing the filter made it
  match.
- The decoy key is matched on the identity, not anywhere in the event:
  an administrator listing the decoy user's keys is not use of the key.
  Searching `RequestParameters` too made that negative match.
- Any result counts. Unlike B4's Entra decoy (an app with a role), an
  AWS decoy user is normally given no permissions, so the attacker's
  calls fail. A rule that wanted success would never fire.
- Decoy secrets are matched by name across every caller, not only the
  decoy key: an attacker who found a real key and then lists secrets is
  caught when they read the decoy secret.

## False positives
- Owners testing their own decoy; secret scanners (GitHub, AWS's own)
  that validate a leaked key. Whether a scanner's validation shows up as
  a CloudTrail call in the key's account was not checked.
- Backup or inventory tools that call `GetSecretValue` on every secret.
  Put decoy secrets where those tools do not reach, or exclude the
  tool's role in triage.

## Tuning
- Negatives tested (6): key id one character away from the decoy; a
  real secret whose name starts with a decoy's name (by name and by
  ARN); a near-name parameter; the decoy name in a CodeBuild request; an
  administrator's `ListAccessKeys` on the decoy user. Each was shown to
  match when its clause was loosened (evidence).
- Production: group alerts by `Token`.

## Test evidence
Run on 2026-11-21 in the Kusto emulator; details in
[tests/evidence.md](tests/evidence.md). 4 of 4 positive cases matched,
0 of 6 negative cases. All samples are hand-written. The recorded
CloudTrail data (6,417 events) returned 0 rows, as expected (no decoy in
it); it shows only that the query runs on real records.

## Blind spots
- Calls CloudTrail does not record. AWS says "some non-authenticated AWS
  STS requests might not be logged"; whether every way to check a key
  (for example `sts:GetCallerIdentity`) is logged was not confirmed from
  an AWS page fetched here. A key validated only by a call that is not
  logged is not seen.
- A `GetParameter` for a decoy that does not exist: AWS says the
  `ParameterNotFound` exception is not recorded in CloudTrail. Create
  the decoy parameter for real.
- A decoy file in S3: object reads are CloudTrail data events, which a
  trail records only when configured to [Likely]. Not covered.
- The decoy account's trail not in Sentinel.
- `requestParameters` key names for SSM (`name`, `names`) follow the API
  field names (`Name`) in CloudTrail's camelCase form; this was not
  checked against a recorded SSM event. The Secrets Manager ARN suffix
  (`-` plus six characters) was not confirmed from a fetched AWS page
  [Likely]; a by-name read is matched either way.
- A careful human who recognises a decoy and leaves it alone.

## References
- AWS, "CloudTrail userIdentity element" (accessKeyId: "If the request
  was made with temporary security credentials, this is the access key
  ID of the temporary credentials"), and "CloudTrail record contents"
  (errorCode, sourceIPAddress),
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html,
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
  (fetched 2026-11-21 through a fetch tool).
- AWS, "AWS CloudTrail entries for Secrets Manager" (GetSecretValue
  entries are "Generated by the GetSecretValue and BatchGetSecretValue
  operations"),
  https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html
  (fetched 2026-11-21).
- AWS, "GetParameter" API reference (`Name`, `WithDecryption`;
  `ParameterNotFound` "is *not* recorded"),
  https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html
  (fetched 2026-11-21).
- AWS, "Logging IAM and AWS STS API calls with AWS CloudTrail",
  https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html
  (fetched 2026-11-21).
- B4 and its references (Microsoft, 2026-11-05).
