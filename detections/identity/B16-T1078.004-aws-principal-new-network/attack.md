# Stolen AWS key used from a new network (T1078.004)

## What the attack is
An attacker holding a workload's access key (long-term, or a role's
temporary key) calls AWS from their own infrastructure. Even when they
rotate IP addresses, they stay on one or a few hosting, proxy or
residential networks the workload has never used.

## How the attack happens
1. The key leaks or is taken from an instance's metadata service.
2. The attacker calls AWS from a VPS or proxy pool, often several IPs.
3. CloudTrail logs each call with `sourceIPAddress`; the workload's own
   calls keep coming from its usual networks.

## Real-world use
- Microsoft (2026-11-05) reports Azure intrusions from attacker
  infrastructure including a Tor exit node. **No fetched source shows
  ARTEX or the same agents on AWS.** The new-ASN idea is the blog
  draft's, ported from B6.

## What it leaves in the logs
`AWSCloudTrail`: `SourceIpAddress`, `UserIdentityArn`, `SessionIssuerArn`,
`UserIdentityType`, `UserIdentityAccessKeyId`, `ErrorCode`. The ASN comes
from `IpAsn_CL`.

## Prerequisites
A stolen key for a principal with at least two weeks of history.

## Mapping
T1078.004 Valid Accounts: Cloud Accounts, initial-access, as B6. IDs
checked with `python -m dac validate --attack-bundle` on 2026-11-21.

## References
- See README.md, References.
