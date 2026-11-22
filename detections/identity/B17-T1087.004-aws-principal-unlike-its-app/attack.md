# Stolen AWS key used for discovery (T1087.004, T1526, T1580)

## What the attack is
After getting a working key, an attacker (or an agent) finds out whose
key it is and what it can reach: identity, users and roles, buckets,
instances, secrets. They use their own tools, not the workload's code,
and they correct failed calls as they go.

## How the attack happens
1. `sts:GetCallerIdentity` to learn the account and principal.
2. `iam:List*`, `s3:ListBuckets`, `ec2:Describe*`,
   `secretsmanager:ListSecrets` and similar.
3. A denied or invalid call is retried with a fixed parameter (another
   bucket name, region or id) within seconds.

## Real-world use
- Microsoft (2026-11-05) describes this on Azure: Graph enumeration and
  failed calls retried after about 28, 60 and 80 seconds. **No fetched
  source shows ARTEX or the same agents on AWS.** Splunk's attack_data
  has recorded AWS discovery by lab scanners (used in the evidence).

## What it leaves in the logs
`AWSCloudTrail`: `EventSource`, `EventName`, `ErrorCode`,
`RequestParameters`, `UserAgent`, `UserIdentityArn`, `SessionIssuerArn`,
`UserIdentityInvokedBy`, `SourceIpAddress`.

## Prerequisites
A stolen key for a principal with at least some history in the last 14
days.

## Mapping
T1087.004 Account Discovery: Cloud Account (IAM users and roles),
T1526 Cloud Service Discovery, T1580 Cloud Infrastructure Discovery
(EC2 / S3 listing), discovery. B7 used T1069.003 for Entra groups; IAM
group listing is part of the same `List*` calls but is not singled out,
so T1069.003 is not claimed. IDs checked with `python -m dac validate
--attack-bundle` on 2026-11-21.

## References
- See README.md, References.
