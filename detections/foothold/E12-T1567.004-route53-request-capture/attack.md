# SSRF or blind command execution confirmed through a request-capture service, on AWS (T1567.004)

## What the attack is
Same attack as [E9](../E9-T1567.004-request-capture-egress/attack.md):
the attacker makes a vulnerable server reach a service that records
every request it gets (webhook.site, an interactsh server), to confirm
SSRF or blind command execution, or to post data out. Here the server
is an AWS workload in a VPC.

## How the attack happens
1. The attacker gets a unique capture URL or DNS name.
2. They put it in a parameter the server fetches (SSRF), or in a
   command they inject (`curl https://<id>.oast.fun`).
3. The server resolves the name through the VPC resolver and connects.
4. The capture service shows the attacker the request: proof, and
   sometimes data in the URL or body.

## Real-world use
- The Phase 4 notes (docs/threats/artex-phase4-foothold.md) record what
  the fetched sources say about out-of-band checks in the ARTEX
  material; see E9 for which claims were checked.
- **No fetched source shows ARTEX against an AWS workload.** This rule
  detects the behaviour on AWS.

## What it leaves in the logs
`AWSRoute53Resolver`: `QueryName` (the capture name), `QueryType`,
`Rcode`, `SrcAddr`, `SrcIds` (instance), `VpcId`, `AccountId`,
`Region`, and DNS Firewall fields if a rule matched.

## Prerequisites
Route 53 Resolver query logging on the VPC, delivered to Sentinel.

## Mapping
T1567.004 Exfiltration Over Web Service: Exfiltration Over Webhook, as
for E9. ID checked with `python -m dac validate --attack-bundle` on
2026-11-21.

## References
- See README.md, References.
