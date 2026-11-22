# AWS workload looks up a request-capture service in DNS

ATT&CK: T1567.004 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

AWS counterpart of [E9](../E9-T1567.004-request-capture-egress/)
(ADR 014). E9 reads Defender for Endpoint network events, so it needs a
sensor on the server. This rule reads the VPC's DNS log, so it also
covers Lambda functions, containers and instances with no sensor.

## Hypothesis
An attacker who has found SSRF or blind command execution proves it by
making the server call a capture service they can watch (webhook.site,
an interactsh server), and may post data there. Before any connection,
the workload resolves the service's name. In a VPC, Route 53 Resolver
query logging records that lookup with the source address and instance.

## Data sources
- `aws-route53-resolver` (cloud platform team): `AWSRoute53Resolver`,
  through Sentinel's Amazon Web Services Route 53 connector. Each VPC
  needs a Resolver query logging configuration that delivers to the
  connector's S3 bucket.
- Workloads using another resolver (their own DNS server, a hard-coded
  public resolver, DNS over HTTPS) are not seen.

## Detection logic
Query in [rule.yaml](rule.yaml).
1. Lower-case `QueryName` and drop a trailing dot.
2. Keep names that equal a listed domain or end with `.` + the domain.
   The list is E9's (webhook.site, dnshook.site and ProjectDiscovery's
   public interactsh servers), verified there.
3. One row per source address, instance, VPC, account, region and
   matched domain, with the names, query types, response codes and any
   DNS Firewall action.

## Why this logic
- DNS rather than flow logs: VPC Flow Logs have addresses, not names,
  and these services sit on shared hosting whose addresses change.
- Exact domain or a subdomain, not a substring: a name containing the
  domain inside another domain (`webhook.site.example.test`) must not
  match; matching with `has` alone made it match. Look-alikes such as
  `notwebhook.site` are kept out by the first filter (`has_any` matches
  whole terms), so dropping the label check alone did not change the
  result.
- Trailing dot stripped: whether the connector keeps DNS's trailing
  dot was not found in the Learn or AWS pages; both forms are tested.
- Any response code: an `NXDOMAIN` for a random interactsh name still
  shows the workload tried.

## False positives
- Developers testing webhooks from a dev VPC. Exclude dev VPCs or
  accounts per customer, or lower severity there.
- Security scanners you run (DAST tools use interactsh for out-of-band
  checks): exclude their source addresses.

## Tuning
- Negatives tested (6): `notwebhook.site`, `webhook.site.example.test`,
  `oast.pros`, `docs.webhook-site.example.test`, an AWS endpoint, and
  `interact.sh` (the project's own site, not a capture server in the
  default list). One loosening made a negative match (evidence).
- Add self-hosted interactsh or Burp Collaborator domains you see in
  your threat intelligence to `capture_domains`.

## Test evidence
Run on 2026-11-21 in the Kusto emulator; [tests/evidence.md](tests/evidence.md).
3 of 3 positive cases matched, 0 of 6 negative cases. All samples are
hand-written; no recorded Route 53 Resolver log is loaded.

## Blind spots
- Lookups that do not go through the VPC resolver (DoH, a resolver on
  the internet, cached answers).
- Self-hosted interactsh servers, Burp Collaborator, other capture
  services and attacker-owned domains (same list limits as E9).
- `SrcIds.instance` is empty for queries from a Resolver endpoint, and
  AWS notes the id "may be unfamiliar" for CloudShell, Lambda, EKS or
  Fargate; the source address is still reported.
- DNS Firewall blocking the name: the query is still logged, with the
  firewall action, and still alerts (the attempt is the signal).

## References
- AWS, "Resolver query log format" (`query_name`, `srcaddr`, `srcids`:
  "IDs of the `instance`, `resolver_endpoint`, and the
  `resolver_network_interface` that the DNS query originated from or
  passed through"),
  https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-format.html
- Microsoft Learn, AWSRoute53Resolver table reference,
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awsroute53resolver
- E9 and its references (webhook.site, ProjectDiscovery interactsh
  README, commit b9fea16).
AWS and Learn pages fetched 2026-11-21 through a fetch tool.
