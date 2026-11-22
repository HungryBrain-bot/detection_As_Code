# AWS IAM user or role calls from a network (ASN) it has not used in 14 days

ATT&CK: T1078.004 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

AWS port of [B6](../B6-T1078.004-sp-new-network/) (ADR 013).

## Hypothesis
A workload identity calls AWS from a small, stable set of networks. A
successful call from an ASN it has not used in 14 days means the key
is being used from somewhere new, which for a workload usually means
someone else has it.

## Data sources
- `aws-cloudtrail` (cloud platform team): `AWSCloudTrail`.
- `ip-asn-lookup` (detection team): `IpAsn_CL` (see B15). Without it the
  rule matches nothing.

## Detection logic
1. Successful calls by `IAMUser` or `AssumedRole` identities from a
   public IPv4 address.
2. The principal is the IAM user ARN, or for a role session the role
   ARN (`SessionIssuerArn`), so every session of a role shares one
   history.
3. ASN from `IpAsn_CL` (`ipv4_lookup`); addresses with no row dropped.
4. Baseline: ASNs per principal before the last hour (up to 14 days,
   the query period). At least 50 baseline calls are required.
5. Alert per principal and new ASN seen in the last hour.
   `BaselineAwsOnly` marks the case the rule was written for: a principal
   only ever seen from Amazon's ASNs.

## Why this logic
- ASN, not IP: workloads in AWS change IPs constantly; an attacker
  rotating IPs on one provider keeps one ASN. Grouping by IP made the
  "new IP, same ASN" negative match.
- Role ARN, not session ARN: a session name changes per session
  (`assumed-role/<role>/<session>`), so per-session history would be
  empty every time.
- 50 baseline calls, not B6's 10 sign-ins: CloudTrail logs every API
  call, so a working day of a workload produces far more rows than
  Entra sign-ins. The number is a starting point, not measured.
- Unmatched addresses dropped: keeping them makes "no ASN" look like a
  new ASN (shown with a negative).

## False positives
- A workload moved to a new region, provider or NAT egress.
- People (`IAMUser` with console or CLI use) travelling or on a new ISP.
  The rule is aimed at workload identities; consider limiting it to
  roles and service users per customer.
- Stale or wrong IP-to-ASN rows.

## Tuning
- Restrict to workload principals (a list of role ARNs or a naming
  convention) where human users are noisy.
- Negatives tested: new ASN with a 30-call baseline; new IP in a known
  ASN; new ASN but the call failed; an address with no lookup row; a
  private address through a VPC endpoint. All but the last were shown to
  match when their clause was loosened; the private-address filter is
  redundant in the samples (no lookup row covers private ranges, so the
  lookup drops the row first) and stays as a guard for lookups that do.

## Test evidence
Run on 2026-11-21 in the Kusto emulator; details in
[tests/evidence.md](tests/evidence.md). 2 of 2 positive cases matched,
0 negatives. All samples hand-written. The recorded CloudTrail data
returned 0 rows: no lookup rows exist for its addresses.

## Blind spots
- An attacker running from AWS when the principal's baseline is AWS
  (same ASN: no alert).
- A principal with fewer than 50 calls in 14 days, or a brand-new one
  (no baseline).
- Failed calls are ignored: a key that is denied everything from a new
  network is not alerted here (D4 and B17 cover parts of that).
- IPv6; `ipv4_lookup` in Log Analytics not verified (see B15).

## References
- As B15 (CloudTrail record contents and userIdentity pages, PeeringDB,
  iptoasn.com, ipv4_lookup), all fetched 2026-11-21.
