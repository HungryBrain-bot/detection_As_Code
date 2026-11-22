# Working through an IDOR on an API behind API Gateway (T1190)

## What the attack is
Broken object-level authorization: the API returns a record to anyone
who asks for its ID, not only to its owner. An attacker who notices
walks the IDs and collects the records. Same attack as
[E1](../E1-T1190-sequential-record-access/attack.md); here the API is
published through Amazon API Gateway.

## How the attack happens
1. The attacker signs in as an ordinary user (or uses no token, if the
   route has none) and reads one of their own records.
2. They change the ID in the path and ask again: in order, at random, or
   from a list.
3. Where authorization is missing they get 200 and the record; where it
   is present, 403 or 404.
4. With a working pattern they pull many records quickly.

## Real-world use
- Wiz (2026-10-22) describes ARTEX agents probing "predictable
  identifiers" for "broken access controls" (`GET /company/1/logins`
  answered 403) on its software-vendor victims; Zscaler (2026-10-14)
  recommends server-side authorization for customer records after the
  Korean intrusions (docs/threats/artex-phase2-recon.md and
  artex-phase4-foothold.md).
- **No fetched source shows ARTEX against an API on API Gateway, or an
  IDOR walk on AWS.** This rule detects the behaviour there.

## What it leaves in the logs
API Gateway access log lines (`AWSCloudWatch.Message`): `path` with the
record ID, `status` (200 / 403 / 404), `responseLength`, `sourceIp`,
`user` (if the format sets it), `requestTimeEpoch`.

## Prerequisites
Access logging in this project's format on the API's stages, shipped to
Sentinel, and at least a day of history for the volume reason.

## Mapping
T1190 Exploit Public-Facing Application, as for E1 (the API is the
public-facing application; IDOR is the flaw exploited). ID checked with
`python -m dac validate --attack-bundle` on 2026-11-21.

## References
- See README.md, References.
