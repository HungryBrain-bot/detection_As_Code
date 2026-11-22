# Stolen AWS access key used alongside the real workload (T1078.004)

## What the attack is
When an access key leaks, the attacker does not replace the workload:
the real application keeps calling AWS with the key from where it runs,
and the attacker calls AWS with the same key from their own
infrastructure. For a while, one key is in use by two parties. Nothing
in a single call looks wrong: no MFA applies to access-key calls.

## How the attack happens
1. The key leaks (public repo, `.env`, CI logs, a container image), or a
   temporary role key is taken from an instance's metadata service.
2. The attacker calls AWS from a VPS, proxy or VPN exit.
3. Meanwhile the workload, running in EC2, ECS, Lambda or EKS, keeps
   calling with the same key from AWS addresses or through VPC
   endpoints.
4. CloudTrail logs both with the same `userIdentity.accessKeyId`.

## Real-world use
- Microsoft (2026-11-05) describes the Azure version of this (secrets
  found on GitHub, used against Entra ID). **No fetched source shows
  ARTEX or the same agents using AWS keys.** The two-network check is
  this project's inference from how hosted workloads call their cloud,
  ported from B5.

## What it leaves in the logs
`AWSCloudTrail`: `UserIdentityAccessKeyId`, `UserIdentityArn`,
`SourceIpAddress`, `VpcEndpointId`, `ErrorCode`, `UserAgent`,
`EventSource` / `EventName`. No ASN: that comes from `IpAsn_CL`.

## Prerequisites
A leaked access key whose real workload runs in AWS (or behind the
customer's own known egress). An attacker who runs their tooling in AWS
defeats the rule.

## Mapping
T1078.004 Valid Accounts: Cloud Accounts, initial-access, as B5. IDs
checked with `python -m dac validate --attack-bundle` on 2026-11-21.

## References
- See README.md, References.
