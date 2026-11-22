# One AWS access key used from AWS's network and from outside it

ATT&CK: T1078.004 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

AWS port of [B5](../B5-T1078.004-credential-two-networks/) (ADR 013).

## Hypothesis
A workload that runs in AWS calls AWS from AWS: from an AWS address,
through a VPC endpoint, or from a private address. If the same access
key id also makes successful calls from another network on the same
day, a second party holds the key.

## Data sources
- `aws-cloudtrail` (cloud platform team): `AWSCloudTrail`.
- `ip-asn-lookup` (detection team): `IpAsn_CL`, a table this project
  defines (schemas/reference/sentinel/IpAsn_CL.yaml), one row per IPv4
  network (CIDR) with its ASN, loaded at least daily from an IP-to-ASN
  dataset such as iptoasn.com's (PDDL). **CloudTrail has no ASN column;
  without this table the rule matches nothing.** Building and running
  the loading job is the customer's (or the detection team's) work; it
  is not built here.

## Detection logic
1. Successful calls (`ErrorCode` empty) with an access key id, from an
   IPv4 `SourceIpAddress`. Calls made by an AWS service for the caller
   log a DNS name or `AWS Internal` instead of an IP and are skipped.
2. ASN from `IpAsn_CL` with the `ipv4_lookup` plugin.
3. Internal: a VPC endpoint id (not `AWS Internal`), a private address,
   or an ASN in `internal_asns` (Amazon's 16509 and 14618 by default,
   plus the customer's own egress ASNs). External: any other ASN.
   Unknown (no lookup row): not counted.
4. Per access key id over the query period (1 day): alert when there
   are both internal and external calls.

## Why this logic
- Per key, not per user: an IAM user can have a CI key used outside AWS
  and an app key used inside; that is two keys, not one stolen. Grouping
  by user made that negative match.
- ASN, not IP: an attacker can rotate IPs but not make their traffic
  come from inside the customer's VPCs or from AWS's network without
  renting AWS capacity (Blind spots).
- Unknown is not external: a lookup gap must not raise alerts. Counting
  unknown as external made a negative match. The cost is silence when
  the lookup is missing, which is why it is a gated log source.
- `AWS Internal` in `vpcEndpointId` is not treated as the customer's
  endpoint: AWS writes that value for AWS-originated events. Treating it
  as internal made a negative match.
- Long-term (AKIA) and temporary (ASIA) keys are both covered: a role
  session's temporary key used outside AWS is the instance-credential
  theft case. The prefix meaning was not confirmed from a fetched AWS
  page, so the rule does not depend on it.
- The `ipv4_lookup` table is projected to `Network, ASN, AsName` first:
  in the emulator, a `TimeGenerated` column in the lookup replaced the
  event's own time after the join, which broke the 14-day logic of B16
  until it was removed.

## False positives
- A workload that legitimately runs both in AWS and elsewhere with one
  key (a hybrid job, a developer copying a production key to a laptop).
  The second is a finding in its own right.
- Customer egress ASNs left out of `internal_asns`.
- IP-to-ASN data that is wrong or stale for an address.

## Tuning
- Add the customer's data-centre and other-cloud ASNs to
  `internal_asns`.
- Negatives tested: same user with a second key outside AWS; app key
  from outside but failed; app key from an address with no lookup row;
  a key only ever used outside AWS; an `AWS Internal` call. Each was
  shown to match when its clause was loosened (evidence).

## Test evidence
Run on 2026-11-21 in the Kusto emulator; details in
[tests/evidence.md](tests/evidence.md). 2 of 2 positive cases matched,
0 negatives matched. All samples hand-written; the ASN rows use
documentation address ranges with 16509 standing in for AWS. The
recorded CloudTrail data returned 0 rows: no lookup rows were loaded
for its addresses (none were invented), so every call is "unknown".

## Blind spots
- An attacker running from AWS (an EC2 instance in any account): their
  calls come from Amazon's ASN and count as internal. This is the
  largest gap and is easy for an attacker to choose.
- IPv6 source addresses (not looked up).
- AWS publishes IP ranges only for "services that customers commonly use
  to perform egress filtering", not all of them; an ASN-based view is
  used instead, which depends on the IP-to-ASN data.
- Whether Amazon announces all AWS service and EC2 address space from
  16509 and 14618 was not checked [Guessing that it is most of it].
- `ipv4_lookup` is documented for Azure Data Explorer and Fabric; the
  page fetched does not list Log Analytics / Sentinel in its "Applies
  to" banner. The rule ran in the ADX emulator only. **Run it once in a
  real Sentinel workspace before relying on it.**

## References
- AWS, "CloudTrail record contents" (sourceIPAddress: "For services in
  AWS, only the DNS name is displayed", AWS-originated events "usually
  `AWS Internal/#`"; vpcEndpointId),
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
  (fetched 2026-11-21 through a fetch tool).
- AWS, "AWS IP address ranges",
  https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html
  (fetched 2026-11-21).
- PeeringDB, AS16509 ("Amazon.com, Inc.", aka "Amazon Web Services")
  and AS14618 ("Amazon.com, Inc.", "Amazon AES"),
  https://www.peeringdb.com/asn/16509, https://www.peeringdb.com/asn/14618
  (fetched 2026-11-21).
- iptoasn.com ("Licensed under Public Domain (PDDL v1.0)", "Updated
  hourly"), https://iptoasn.com/ (fetched 2026-11-21).
- Microsoft Learn, "ipv4_lookup plugin",
  https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/ipv4-lookup-plugin
  (fetched 2026-11-21).
