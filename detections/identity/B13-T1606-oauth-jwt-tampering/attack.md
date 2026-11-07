# Forged JWTs and tampered OAuth callbacks (T1606, T1190)

## What the attack is
The attacker sends the application authentication inputs it made up: a
JWT with no signature (`alg: none`) or a forged one, an OAuth callback
with a fabricated authorization code or a malformed `state`, or an
authorization request with its own `redirect_uri`. If the app does not
check signatures, `state` or exact redirect URIs, one of these logs the
attacker in or sends a victim's code to the attacker.

## How the attack happens
1. Find the app's OAuth callback and token-accepting routes (from its scripts, Phase 2).
2. Send a token with header `{"alg":"none"}` and claims of the attacker's choice, with and without a signature.
3. Call the callback with invented `code` and `state` values, and authorization requests with altered `redirect_uri`.
4. Watch for any response other than a rejection.

## Real-world use
Wiz (2026-10-22), for an ARTEX-using actor overlapping with Storm-0940: "manipulate OAuth callbacks and state parameters, test unsigned JWTs"; "the agent directly manipulated the callback endpoint by injecting fabricated authorization codes and malformed state parameters, while also attempting to bypass authentication using unsigned JWTs"; `GET /sso?jwt=eyJhbGciOiJub25lIn0...`; "Although most of these attempts failed". Wiz does not mention `redirect_uri`. See docs/threats/artex-phase3-identity.md.

## What it leaves in the logs
Only what the app logs. Web access logs show the request paths (and, for GET, the query string with the token or `state`, which should not be logged in full). A gateway that validates JWTs may log the failure reason (API Management's validate-jwt reasons); none logs a failed `state` check. B13 expects the app to write `AppAuthEvent_CL` rows.

## Prerequisites
A reachable app that accepts JWTs or runs an OAuth client flow. No credentials.

## Mapping
T1606 Forge Web Credentials ("credentials are new and forged by the adversary, rather than stolen") for unsigned or forged JWTs; T1190 Exploit Public-Facing Application for using a missing `state`, signature or redirect check (a "software bug ... or a misconfiguration"). Tactics credential-access, initial-access. Not T1550 (stolen, not forged, material). Checked against the ATT&CK enterprise bundle (mitre/cti master, fetched 2026-11-07).

## References
- Wiz Research, 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- MITRE ATT&CK T1606, T1190 (bundle fetched 2026-11-07).
