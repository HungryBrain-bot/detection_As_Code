# Service principal signs in from a network (ASN) it has not used in 14 days

ATT&CK: T1078.004 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If an attacker uses a service principal's stolen secret, at least some
of their sign-ins will come from an ASN that the service principal has
not signed in from in the previous 14 days, however many IP addresses
they rotate through.

## Data sources
- `entra-sp-signin` (identity team): `AADServicePrincipalSignInLogs`,
  14 days retained in the workspace (the query period).
- Needs `AutonomousSystemNumber`; rows without it are ignored (not
  checked against a live tenant; the recorded lab records lack it).

## Detection logic
1. Successful sign-ins with an ASN.
2. Baseline: per service principal, the set of ASNs and the count of
   sign-ins from 14 days ago to 1 hour ago.
3. Last hour: per service principal and ASN, sign-ins, IPs, resources,
   credential key ids.
4. Alert on an ASN not in the baseline, for service principals with at
   least 10 baseline sign-ins. `BaselineMicrosoftOnly` is true when
   every baseline ASN is 8075, the case of a credential only ever used
   from Azure now seen elsewhere, the strongest version of the signal.

## Why this logic
- ASN, not IP: IPs churn inside a cloud provider (false positives) and
  attackers rotate them (false negatives). An ASN is a stable proxy for
  "network type". It is a proxy only: the rule does not know whether an
  ASN is a hosting provider, a residential ISP or a mobile carrier;
  that would need an ASN-type enrichment the project does not have.
- Alternative, per-IP novelty: alerts on every scale-out of the real
  app; useless for agents that rotate IPs.
- Alternative, B5 alone: needs the real app to be running in Azure on
  the same credential in the same day; B6 also catches the attacker
  after the real app stopped, or for apps hosted outside Azure.
- Minimum 10 baseline sign-ins: without history there is no normal.
  Tested: a 3-sign-in app with a new ASN does not alert.
- Failed sign-ins excluded: a failure from a new ASN can be someone
  holding an old or wrong secret; worth hunting, too noisy to alert on
  (tested negative).

## False positives
- The app moves (new region, new cloud, new egress NAT provider), or a
  developer runs it locally once.
- Microsoft or a CDN changes which ASN announces a range.
- Apps that sign in from many ASNs (client-side apps shipped to
  customers): the 100-ASN cap on the baseline set means a very diverse
  app can re-alert on ASNs it has used. Exclude those apps.

## Tuning
- Negatives tested: new IP in a known ASN; new ASN with only 3 baseline
  sign-ins; an ASN already in the baseline; a failed sign-in from a new
  ASN. Each matched when its clause was removed.
- Production: exclude apps that run on end-user devices; raise severity
  when `BaselineMicrosoftOnly` is true; group alerts by service
  principal.

## Test evidence
Run on 2026-11-07 in the Kusto emulator with timestamps shifted so the
newest event is two minutes old (`rebase_time`, the query uses
`ago()`); details in [tests/evidence.md](tests/evidence.md). 2 of 2
positive cases matched (26 events), 0 of 43 negatives. All samples are
hand-written (generated from a short script, each labelled). Recorded
service principal sign-ins: 0 rows, because none has an ASN.

## Blind spots
- Attacker infrastructure in an ASN the app already uses, above all
  Azure (AS8075) for an Azure-hosted app.
- New apps and rarely used apps (fewer than 10 sign-ins in 14 days).
- An attacker active for over 14 days becomes part of the baseline.
- Sign-ins with no ASN.

## References
- Microsoft, "Threat actors use agentic AI tooling to find and abuse
  exposed secrets", 2026-11-05 (fetched 2026-11-07).
- `AADServicePrincipalSignInLogs` reference schema in
  `schemas/reference/sentinel/`.
