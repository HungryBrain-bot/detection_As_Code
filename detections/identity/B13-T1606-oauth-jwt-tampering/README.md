# Unsigned JWT, or repeated OAuth callback and token tampering from one client network (schema-dependent)

ATT&CK: T1606, T1190 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
A legitimate client never sends a JWT whose header says `alg: none`, and
rarely fails `state`, `redirect_uri`, code or signature checks more than
once or twice. A client network that does, especially in more than one
way, is testing whether the app validates them.

**Schema-dependent.** This rule reads `AppAuthEvent_CL`, a table this
project defines. It returns nothing until the application, or its auth
middleware, writes one row per rejected OAuth callback or JWT (data
prerequisite below). Do not count it as coverage before that table has
rows.

## Data sources
- `app-auth-events` (app platform team): `AppAuthEvent_CL`, columns and allowed values in `schemas/reference/sentinel/AppAuthEvent_CL.yaml`.
- Data prerequisite: the app logs, for every rejection, `EventType` (oauth_state_mismatch, oauth_redirect_rejected, oauth_code_rejected, jwt_rejected), `Reason` (for JWTs: alg_none, signature_invalid, alg_not_allowed, malformed, expired, issuer, audience, key_not_found), `JwtAlg` (the header value as received), `ClientIp` (the real client, not a proxy), path, app, user agent. Never the token, code or state value.
- Why not a vendor log: no vendor log found records a failed `state` check. Azure API Management's validate-jwt errors (TokenSignatureInvalid, JwtInvalid, ...) are documented, but Microsoft does not say they appear in `ApiManagementGatewayLogs.LastErrorReason`, and APIM logs no `alg`. A feed from APIM is parked.

## Detection logic
```kql
// B13: OAuth callback / JWT tampering, schema-dependent (detections/identity/B13-T1606-oauth-jwt-tampering/README.md)
    let window = 30m;
    let min_rejections = 3;
    let min_kinds = 2;
    let oauth_types = dynamic(["oauth_state_mismatch", "oauth_redirect_rejected", "oauth_code_rejected"]);
    // Token rejections a valid client does not cause. expired, issuer, audience and key_not_found are left out:
    // stale tokens and misconfigured clients cause them.
    let tampering_jwt = dynamic(["alg_none", "signature_invalid", "alg_not_allowed", "malformed"]);
    let net = (ip: string) { iff(ip contains ":", strcat(substring(parse_ipv6(ip), 0, 19), "::/64"), format_ipv4_mask(ip, 24)) };
    AppAuthEvent_CL
    | where isnotempty(ClientIp)
    | extend AlgNone = EventType == "jwt_rejected" and (Reason == "alg_none" or JwtAlg =~ "none")
    | where EventType in (oauth_types) or (EventType == "jwt_rejected" and (Reason in (tampering_jwt) or AlgNone))
    | extend Kind = iff(EventType == "jwt_rejected", strcat("jwt_", iff(AlgNone, "alg_none", Reason)), EventType)
    | extend Network = net(ClientIp), Window = bin(TimeGenerated, window)
    | summarize Rejections = count(), Kinds = make_set(Kind), KindCount = dcount(Kind), AlgNoneTokens = countif(AlgNone),
                Apps = make_set(AppName, 10), Paths = make_set(RequestPath, 20), RedirectUris = make_set_if(RedirectUri, isnotempty(RedirectUri), 10),
                IPAddresses = make_set(ClientIp, 10), UserAgents = make_set(UserAgent, 10),
                FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Network, Window
    | where AlgNoneTokens > 0 or Rejections >= min_rejections or KindCount >= min_kinds
    | extend Reason = case(AlgNoneTokens > 0, "unsigned JWT (alg none) presented", KindCount >= min_kinds, "several kinds of tampering", "repeated tampering")
    | extend TimeGenerated = LastSeen
    | project TimeGenerated, Reason, Network, Window, Rejections, KindCount, Kinds, AlgNoneTokens, Apps, Paths, RedirectUris, IPAddresses, UserAgents, FirstSeen, LastSeen
```
1. Keep OAuth rejections and JWT rejections whose reason is alg_none, signature_invalid, alg_not_allowed or malformed (or whose `JwtAlg` is "none").
2. Per source network (IPv4 /24, IPv6 /64) and 30-minute window: alert on any alg-none token; otherwise on 3 or more such rejections, or 2 or more kinds.

## Why this logic
- Wiz logged both: the agent "manipulated the callback endpoint by injecting fabricated authorization codes and malformed state parameters" (`GET /sign_in/oauth/microsoft/callback?code=AAAA&state=notvalidb64!!`) and sent a token that "decodes to `{"alg":"none"}` and `{"email":"test@test.com"}`", to "more than 60 variations of SSO routes ... in just two minutes".
- An alg-none token alerts alone: no library issues one for real use.
- Expired, wrong issuer, wrong audience and unknown key are left out: stale and misconfigured clients cause them (tested: 10 expired tokens and 3 misconfigured ones, no alert). A forged token with a real `alg` that fails the signature is still counted.
- Two kinds count: one stale-tab `state` failure is normal; a refused code plus a bad signature from one network is not.
- Thresholds (3 rejections, 2 kinds, 30 minutes) are this project's.

## False positives
- Load tests or security scanners run by your own team (exclude by network).
- A front-end bug that loses `state` (many users, many networks: does not group into one network unless behind shared egress).
- Key rotation mistakes: a client signing with a retired key gives signature_invalid repeatedly. Check the client before treating it as an attack.

## Tuning
- Negatives tested (5 scenarios): 10 expired-token retries; 2 `state` mismatches from one user; 3 misconfiguration rejections (issuer, audience, key); 3 `state` mismatches from three networks; 2 mismatches at the end of a window and 1 at the start of the next. Loosenings that made them match: expired and misconfiguration counted (2 rows), 3 rejections to 2 (2), network grouping removed (1), window 30 minutes to 1 hour (1).
- Set `ClientIp` from the real client address if the app sits behind a proxy or Front Door; otherwise every client is one network.

## Test evidence
Run on 2026-11-07 in the Kusto emulator (details: [tests/evidence.md](tests/evidence.md)). 4 of 4 positive cases matched, 0 of 21 negative events. All samples are hand-written; no recorded data exists for this table.

## Blind spots
- Everything, until the app writes the table.
- Rejections the app does not log (a library that rejects silently).
- Tampering the app accepts: an app that does not validate `state` or signatures writes no rejection, which is exactly the bug. Test for it in CI (hardening guidance); this rule only sees failed attempts.
- A slow probe under 3 rejections per network per window with one kind and no alg-none.

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Microsoft Learn, API Management validate-jwt policy and error-handling policies; ApiManagementGatewayLogs table reference (fetched 2026-11-07)
- docs/threats/artex-phase3-identity.md; ADR 011.
