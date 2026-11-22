# 013. AWS port of the Phase 1 workload-identity rules (B14-B17)

## Status
Accepted (2026-11-21)

## Context
ADR 009 built four Sentinel rules for ARTEX Phase 1 (credential
sourcing) on Azure: B4 honeytoken use, B5 one credential from two kinds
of network, B6 a new ASN, B7 a service principal unlike its app. On
2026-11-21 the owner asked, in the project thread, for the same phase
"in aws env": the same checks for leaked AWS keys. The coordinator had
proposed four rules and suggested dropping the B7 port because it
overlaps D4; the owner did not choose, so all four were built and the
overlap is written down (B17 README).

No fetched source shows ARTEX, or the agents Microsoft described on
2026-11-05, using AWS credentials. These rules target the same
behaviour on AWS; they are not evidence that those actors do it.

## Decision
1. Four Sentinel-only, `targeted`, `status: test` rules, all reading
   `AWSCloudTrail` (the Sentinel AWS S3 connector, already a gated log
   source for D4): B14 decoy access key used or decoy Secrets Manager /
   SSM secret named; B15 one access key id from inside AWS and outside
   it in a day; B16 an IAM user or role from an ASN new in 14 days; B17
   two of new client, five or more new discovery calls, fix-and-retry
   within 60 s. Numbered after B13 because B4-B7 are taken; each README
   links its Azure original.
2. ASN enrichment. CloudTrail records `sourceIPAddress` but no ASN, and
   Sentinel has no built-in IP-to-ASN function for arbitrary tables.
   B15 and B16 read `IpAsn_CL`, a table this project defines (CIDR,
   ASN, AS name), joined with the `ipv4_lookup` plugin. Suggested source
   iptoasn.com (PDDL, hourly), converted from ranges to CIDRs and
   re-sent at least daily by a job the detection team owns
   (`ip-asn-lookup` log source). The job is not built here. Without the
   table both rules match nothing, which the gate's confirmation covers.
3. "Inside AWS" (B15) is a VPC endpoint id that is not `AWS Internal`,
   a private address, or an ASN in `internal_asns` (16509 and 14618,
   registered to Amazon.com on PeeringDB, plus the customer's own). AWS's
   ip-ranges.json was considered and not used: AWS says it publishes
   ranges only for "services that customers commonly use to perform
   egress filtering", and one ASN table serves both rules.
4. Calls whose `sourceIPAddress` is not an IPv4 address (AWS services
   acting for the caller log a DNS name or `AWS Internal`) are skipped by
   B15 and B16; B17 skips calls with `invokedBy`.
5. A role's sessions are one principal (`SessionIssuerArn`) in B16 and
   B17, since session ARNs change per session.
6. `Honeytoken_CL` gains `TokenType` values `AwsAccessKeyId` and
   `AwsSecretName`. Decoy keys match on `userIdentity.accessKeyId` with
   any result: an AWS decoy user normally has no permissions.
7. Harness: `from_cloudtrail` now maps `SessionIssuerArn`,
   `SessionIssuerType`, `VpcEndpointId`, `UserIdentityInvokedBy` and
   `RequestParameters` (JSON text); `rebase_time` now shifts raw
   CloudTrail `eventTime` (before this, B16 and B17's recorded runs saw
   2021 timestamps and nothing in the last hour); `IpAsn_CL` rows load
   as they are.

## Consequences
- Evidence is hand-written only. The recorded CloudTrail sets (Splunk
  attack_data, lab scanners, 2021) return 0 rows for all four: no decoy,
  no ASN rows for their addresses (none were invented), and the scanner
  users have no history for B17 to compare with.
- B15 and B16 are blind to attackers who run from AWS (Amazon's ASN).
  That is cheap for an attacker and is the main weakness of both.
- `ipv4_lookup`'s Learn page lists Azure Data Explorer and Fabric in its
  "Applies to" banner, not Log Analytics. B15 and B16 ran only in the
  ADX emulator; they must be run once in a real workspace first.
- In the emulator, a `TimeGenerated` column in the lookup table replaced
  the event's own time after `ipv4_lookup`; the rules project the lookup
  to `Network, ASN, AsName` first. Found by B16's positives failing.
- Some recorded user agents are logged in brackets (`[aws-cli/...]`);
  B17 strips the bracket before taking the client family.
- 17 identity rules (B1-B17), 36 rules in total.
- Unverified: whether `sts:GetCallerIdentity` and other ways to test a
  key are always logged (AWS says "some non-authenticated AWS STS
  requests might not be logged"); SSM's `requestParameters` key names;
  the Secrets Manager ARN suffix format; that the AKIA / ASIA prefixes
  mean long-term / temporary (the rules do not rely on it).

## Alternatives considered
- Amazon GuardDuty findings (e.g. instance credentials used outside
  AWS): better where enabled, and B15's instance-credential case is
  what they are for; not every customer runs GuardDuty, and its findings
  are not CloudTrail. Not checked here which findings exist today.
- Sentinel's `geo_info_from_ip_address()`: returns location, not ASN.
- Drop B17 as the coordinator suggested: kept, because it is
  baseline-relative and catches quiet discovery D4 cannot; the overlap
  is a loud sweep by a principal with history.
