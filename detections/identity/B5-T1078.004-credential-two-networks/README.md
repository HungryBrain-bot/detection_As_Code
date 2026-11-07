# One service principal credential signs in from Microsoft's network and from outside it

ATT&CK: T1078.004 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If a service principal's secret is used by an attacker while the real
app keeps running in Azure, the same `ServicePrincipalCredentialKeyId`
will have successful sign-ins from AS8075 (Microsoft) and from another
ASN within one day.

## Data sources
- `entra-sp-signin` (identity team): `AADServicePrincipalSignInLogs`,
  which needs the `ServicePrincipalSignInLogs` diagnostic category sent
  to the workspace.
- The rule depends on `AutonomousSystemNumber` being filled; sign-ins
  without it are ignored. Whether every tenant fills it for service
  principal sign-ins was not checked (the recorded Splunk records have
  no ASN at all).
- Tier targeted: it only makes sense for customers whose apps run in
  Azure, and `internal_asns` must be set per customer.

## Detection logic
1. Successful sign-ins (`ResultType == "0"`) with a credential key id
   and an ASN.
2. Each sign-in is "internal" if its ASN is in `internal_asns`
   (default `8075`, Microsoft) and "external" otherwise.
3. Per service principal and credential key id over the query period
   (1 day): counts, IPs and ASNs on each side, resources reached.
4. Alert when one credential has both internal and external sign-ins.

## Why this logic
- Per credential key id, not per app: an app can legitimately have two
  credentials, one used in Azure and one by a CI runner elsewhere
  (tested negative). Two networks on *one* credential is the leak.
- Network kind (ASN), not IP: Azure egress IPs churn, and an attacker
  rotating IPs is still outside AS8075.
- Alternative: Entra ID Protection workload identity risk (leaked
  credentials, anomalous sign-ins). Better where licensed (Workload
  Identities Premium); this needs only the sign-in log.
- Alternative: Conditional Access for workload identities with a named
  location. Prevents instead of detects, but is a licensed feature and
  breaks apps whose egress is not pinned. Recommend it alongside.
- One day, not one hour: a nightly batch app may sign in only once a
  day; a shorter window would miss the overlap. Cost: up to 24
  re-alerts (Tuning).

## False positives
- An app that genuinely runs in two places with one secret (Azure and
  a developer laptop, or Azure and another cloud). This is still a
  finding, secret sharing, but not an intrusion. Add the other
  location's ASN to `internal_asns` or give it its own credential.
- CI runners and SaaS tools that hold the app's secret: those hosted in
  Azure appear internal, those hosted elsewhere external. Which
  providers host where was not checked.
- Customers with on-premises or multi-cloud workloads must list those
  ASNs, or every such app alerts.

## Tuning
- Negatives tested: two credentials on two networks; an external
  sign-in that failed; an external sign-in with no ASN; an app that only
  runs outside Azure. Each matched when its clause was removed.
- Production: set `internal_asns` per customer; group alerts by
  `ServicePrincipalCredentialKeyId` so the hourly runs over one day make
  one incident.
- Not built: also alert on a failed external sign-in (AADSTS7000215)
  followed by success, which Microsoft calls urgent. Parked.

## Test evidence
Run on 2026-11-07 in the Kusto emulator; details in
[tests/evidence.md](tests/evidence.md). 1 of 1 positive case matched
(4 events), 0 of 6 negatives. All samples are hand-written. The 10
recorded service principal sign-ins (Splunk attack_data) returned 0
rows because none of them has an ASN, so the dataset run says nothing
about false positives.

## Blind spots
- Attacker infrastructure inside Azure (a VM or Function in any
  tenant): it is AS8075 too, so the stolen use looks internal. This is
  the biggest gap; B6 does not close it either.
- Apps that do not run in Azure: no internal side to compare with.
- The real app not signing in during the day (stopped, or the attacker
  rotated the secret and locked it out).
- Certificate credentials should work the same way (they have a key id
  too). Federated credentials (workload identity federation) are
  expected to fill `FederatedCredentialId` instead and so are skipped;
  neither was checked against a live tenant.
- Sign-ins with no ASN.

## References
- Microsoft, "Threat actors use agentic AI tooling to find and abuse
  exposed secrets", 2026-11-05 (fetched 2026-11-07).
- Microsoft Learn, "Internet peering overview": AS8075 is Microsoft's
  global network (fetched 2026-11-07).
- `AADServicePrincipalSignInLogs` reference schema in
  `schemas/reference/sentinel/`.
