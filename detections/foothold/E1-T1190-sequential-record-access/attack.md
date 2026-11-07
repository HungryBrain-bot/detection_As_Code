# Reading other users' records through an IDOR (T1190)

## What the attack is
An insecure direct object reference (IDOR) is an authorisation bug: the
application returns a record for any ID the caller asks for, without
checking the record belongs to the caller. An attacker who finds one can
read other customers' records one by one. For a financial portal that is
a data breach without any malware.

## How the attack happens
Described at the level a defender needs; no exploit steps are given.
1. The attacker has a session on the app (often their own customer
   account, sometimes none) and sees a record ID in a URL or parameter.
2. They request the same route with other IDs and compare the answers.
   Answers that contain someone else's data confirm the bug.
3. They keep going through the ID space, usually in order, and save what
   comes back.
Automated tools and scripts do step 3 tirelessly; the owner's draft makes
the point that an agent does not get bored the way a human tester does.

## Real-world use
No fetched source reports IDOR exploitation by ARTEX or Storm-3358.
- Wiz (2026-10-22) says the ARTEX playbook tries to "manipulate
  predictable identifiers to probe for broken access controls and
  unauthorized cross-tenant data access", and logs `GET /company/1/logins`
  answered 403.
- Zscaler (2026-10-14) reports SQL injection and authentication bypass in
  Korean financial portals, and recommends alerting "on sequential lookups
  and unusually high numbers of records accessed per session".
- Recorded Future (2026-10-16) recommends watching for "repeated requests
  for different customers' records".
- CrowdStrike (2026-10-07) reports data breaches at a "loan progress
  inquiry service" without naming the technique.
See docs/threats/artex-phase4-foothold.md.

## What it leaves in the logs
Web access log rows with the same client, the same route and changing
IDs, close together in time; a mix of 200 and 403/404 if some records are
protected; more bytes per client than usual. In `AppServiceHTTPLogs`:
`CIp`, `CsUsername`, `CsUriStem`, `CsUriQuery`, `ScStatus`, `ScBytes`.
The attacker controls speed, order, source IP and user agent; the IDs
themselves have to be in the request.

## Prerequisites
A reachable app with the bug, and usually a valid session (any customer
account).

## Mapping
T1190 Exploit Public-Facing Application, tactic initial-access: the
weakness is "a software bug" in an Internet-facing application (ATT&CK).
T1213 (Data from Information Repositories) and T1213.006 (Databases) were
considered and not used: the data is read through the application's own
API, not from a repository or database the attacker reaches directly.
Checked against the enterprise bundle (mitre/cti master, fetched
2026-11-07).

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Zscaler ThreatLabz, 2026-10-14, https://www.zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean (fetched 2026-11-07)
- Recorded Future, 2026-10-16, https://www.recordedfuture.com/blog/tag-217-artex-south-korean-banks (fetched 2026-11-07)
- CrowdStrike, 2026-10-07, https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/ (fetched 2026-11-07)
