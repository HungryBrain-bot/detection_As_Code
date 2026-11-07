# 011. Identity attack rules: spraying, multi-flow clients, recovery, legacy auth, OAuth/JWT (B8-B13)

## Status
Accepted (2026-11-07)

## Context
Phase 3 of the owner's blog series on agentic attacks (ARTEX and
similar tools) describes an agent working through every way into a
login: password spraying against Okta and Entra ID, OAuth callback and
`state` tampering, unsigned JWTs, account-recovery abuse and probing of
SSO and Microsoft 365 endpoints. The owner asked, in the project thread
on 2026-11-07, for five detections and a hardening list. This adds six
rules beyond the original ten (CLAUDE.md, Scope); the request was
explicit. Claims are checked in docs/threats/artex-phase3-identity.md.

## Decision
1. Six Sentinel-only, `targeted` rules in `detections/identity/`,
   continuing the B series: B8 Entra spray, B9 Okta spray, B10 one client
   network across several Entra login flows, B11 SSPR for several users,
   B12 legacy protocol / ROPC probing, B13 OAuth callback and JWT
   tampering. Hardening items are guidance in the threats file.
2. **One rule per log source set the gate can confirm.** The log-source
   gate needs every source a rule reads, and a KQL `union` over a table
   that does not exist fails. A tenant with Entra but not Okta (or no
   application auth log) would have the whole rule held back. So the
   owner's (a) is split into B8 (Entra) and B9 (Okta), and the two
   application behaviours of (b) are in B13, not B10. B10 covers the
   three behaviours Entra logs record. Correlating B10 and B13 alerts is
   left to Sentinel incidents and parked.
3. **Spraying is counted per account, not per IP** (B8, B9), as the
   owner asked. An account counts in a one-hour round when it fails
   with a wrong password or lockout (Entra 50126/50053; Okta
   `user.session.start` INVALID_CREDENTIALS / VERIFICATION_ERROR, or
   `user.account.lock`) and does not also succeed in that round, which
   removes users who mistype and then sign in. Two triggers: breadth (15
   accounts in a round) and re-targeting (5 accounts failing in two or
   more spray rounds of 10 accounts). The number of IPs and failures per
   IP are reported, not required: Microsoft's documented Storm-0940
   spray was high volume from one address, so requiring "many IPs, few
   attempts each" would have missed it.
4. **"One client" is the source network**: IPv4 /24, IPv6 /64 (B10-B13).
   It is the only key present in sign-in, audit and app logs alike; user
   agents rotate ("constantly circulate user agents", Wiz) and there is
   no shared session id across these logs. Three of Wiz's five IOC
   addresses share one /24. It also groups many real users behind one
   NAT, which is B10's main false positive.
5. **Legacy authentication** (B10, B12) is `ClientAppUsed` in the union
   of the two legacy lists in Microsoft's own Sentinel content
   (Azure-Sentinel c0c2dc2), compared case-insensitively, or
   `AuthenticationProtocol` "ropc". Microsoft publishes no value list.
   The ROPC clause is needed: recorded MFASweep ROPC sign-ins log as
   "Mobile Apps and Desktop clients". B12 also alerts on any legacy or
   ROPC sign-in whose password was accepted (0, 50076, 50079); treating
   50076/50079 as "password accepted" is an inference (Entra asks for MFA
   after the first factor), not stated in the error-code text.
6. **Recovery abuse is Entra only** (B11, and B10's reset leg). Activity
   names are from Microsoft's SSPR reporting page. The initiator IP is
   read from `InitiatedBy.user.ipAddress`; that SSPR records carry it is
   not verified. Okta is not built: the event-type catalog could not be
   read, and Microsoft's own hunting query treats
   `user.account.reset_password` as an admin reset.
7. **B13 is schema-dependent.** It reads `AppAuthEvent_CL`, defined by
   this project (schemas/reference/sentinel/AppAuthEvent_CL.yaml), with
   one row per rejected OAuth callback or JWT, written by the app. No
   vendor log records a failed `state` check; API Management's
   validate-jwt errors are documented but not shown to land in
   `ApiManagementGatewayLogs`, and APIM logs no `alg`. Any `alg: none`
   token alerts on its own; otherwise 3 tampering rejections, or 2
   kinds, per network in 30 minutes. Expired, wrong-issuer, wrong-audience
   and unknown-key rejections are not counted.
8. **Okta in Sentinel is the `OktaSSO` table**, with the column names and
   types from Microsoft's KQL validation table definition (Azure-Sentinel
   c0c2dc2), the table Microsoft's own Okta rules read. `OktaV2_CL`
   (connector v2) is not covered. The harness maps raw Okta System Log
   events to it by flattening keys and adding the type suffix
   (`harness/mapping.py`, `from_okta`).
9. Thresholds are this project's choices. Wiz gives rates ("median gap
   between authentication attempts was strictly one second", bursts of
   20 to 60 minutes, "more than a dozen login attempts" for some users),
   Microsoft gives volumes (327 accounts, 151,000+ failures); neither
   gives an account count per hour or a multi-flow window. The 30-minute
   window is the draft's.
10. New log sources `okta-system-log` (identity team) and
    `app-auth-events` (app platform team); six Splunk attack_data sets
    pinned (two Entra sprays, one brute force, one admin reset, an Okta
    spray and an Okta lockout set).

## Consequences
- Evidence varies by rule. B8 caught both recorded Entra sprays
  (distributed: 31 accounts from 30 IPs; one IP: 31 accounts) and not
  the one-account brute force. B12 caught the recorded MFASweep ROPC
  attempts. B9's only recorded Okta data (10 accounts, then 7 lockouts
  on another day) is below its threshold and returns nothing. B10, B11
  and B13 have no recorded data; all positives are hand-written.
- B13 does nothing until an app writes `AppAuthEvent_CL`; the gate's
  reminder to the app platform team is the control.
- B8 and B9 re-alert on each hourly run while a spray is inside the
  six-hour query period; Sentinel alert grouping is the expected
  mitigation, not built.
- Splitting by source keeps rules deployable per tenant at the cost of
  one more rule (B9) and no single cross-source view.

## Alternatives considered
- One spray rule over `union isfuzzy=true` of Entra and Okta: the gate
  would still need both sources, and the schema check would report the
  missing table as a gap.
- Per-IP spray thresholds (Microsoft's Okta rule: more than 15 users from
  one IP in 5 minutes): this is what IP rotation defeats, and what the
  owner asked not to build.
- B10 keyed on user agent or Okta device fingerprint: rotated by the
  agent, and absent from audit and app logs.
- B13 on `ApiManagementGatewayLogs`: real vendor table, but it sees no
  OAuth callback and no `alg`, and the reason-to-column link is not
  documented.
