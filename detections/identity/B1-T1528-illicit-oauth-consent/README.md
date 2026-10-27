# Delegated OAuth consent or grant with mailbox, file or directory-write scopes

ATT&CK: T1528 · Severity: Medium · Status: test · Tier: baseline · Targets: sentinel

## Hypothesis
If an attacker gets an app consented to (by phishing a user, or with an
admin account they hold), the Entra audit log will show a successful
`Consent to application` or `Add delegated permission grant` whose
granted scopes include a permission that reads or changes mail, files,
contacts or the directory.

## Data sources
- Log source `entra-audit` (owner: identity team): Entra ID audit logs
  in the Sentinel `AuditLogs` table (Microsoft Entra ID data connector,
  or diagnostic settings to the workspace).
- Fields: `OperationName`, `Result`, `TargetResources`
  (`modifiedProperties`), `InitiatedBy`, `CorrelationId`,
  `TimeGenerated`.
- Tier baseline: `AuditLogs` is the same table in every tenant that
  sends Entra audit logs to Sentinel, so the gate's schema probe can
  confirm it without a per-customer decision. The rule still deploys
  only where the probe (or the identity team) confirms the table.

## Detection logic
Full query in `rule.yaml`. In order:
1. `Consent to application` or `Add delegated permission grant`, with
   `Result` success.
2. For each target resource, the modified properties are folded into
   one bag, and the granted text is read from
   `ConsentAction.Permissions` (consent) or
   `DelegatedPermissionGrant.Scope` (grant).
3. For a consent, only the text after `=>` (the new grants) is kept,
   and every `Scope: ...` list in it is extracted, so a consent that
   writes several grants is read in full.
4. The scopes are split on spaces, lower-cased, and intersected with a
   fixed list of 23 high-risk delegated scopes (mail read/send/shared,
   mailbox settings, EWS, files, sites, notes, contacts, user and
   directory write, application and app-role management). Exact
   membership, so `Mail.ReadBasic` does not count as `Mail.Read`.
5. One row per `CorrelationId`: the consent and the grant it creates
   share one, so a single consent raises a single alert, with the
   targets, the risky scopes, the consent type (`Principal` for one
   user, `AllPrincipals` for the tenant), whether it was admin consent,
   and who did it from which IP.

## Why this logic
- Alternative 1, alert on every consent (Microsoft's "Rare application
  consent" style): catches benign-scope consents, but every SaaS
  sign-up with "Sign in with Microsoft" consents to `User.Read`; the
  volume hides the dangerous ones. Gating on what the app can actually
  do with the token keeps the alert to grants that give data access.
- Alternative 2, `Consent to application` only: misses the direct
  grant through Graph or PowerShell by an attacker who already has an
  admin account, which writes only `Add delegated permission grant`
  (the recorded OTRF intrusion is this case).
- Alternative 3, `contains` on the scope text: substring matching
  makes `Mail.ReadBasic` look like `Mail.Read` (tested: a `contains
  "mail.read"` version matches the `Mail.ReadBasic` negative). Exact set
  membership after splitting is cheap and precise; Microsoft's own
  `EndUserConsentMailboxOfflineAccess` rule makes the same choice.
- Alternative 4, only consents to unverified or newly seen apps: needs
  a publisher-verification or baseline lookup the audit row does not
  carry; left to tuning.

## False positives
- Legitimate mail, calendar or file integrations (CRM plug-ins, e-mail
  signature tools, backup products) consented by users or admins.
  Expect them at roll-out; allowlist by app id after review.
- Admin consent during planned onboarding of an enterprise app: the row
  says `AllPrincipals` and admin consent; change tickets explain them.
- Re-consent to an app that already had a risky scope (for example
  after adding `User.Read`) alerts again, because the new grant lists
  all its scopes, old and new.

## Tuning
- Recorded data showed the consent and its grant as two events with one
  correlation id; one row per `CorrelationId` keeps one alert per
  consent (tested: the recorded pair gives one row).
- An allowlist of approved client app ids (`AdditionalDetails` `AppId`,
  or the `Consent to application` target id) is the first tuning step
  per customer.
- The scope list is a judgment, not a vendor list: it covers what the
  cited reports name (`Mail.Read`, `Mail.Send`) and the scopes that give
  file, site or directory-write access. Customers that consider
  `offline_access` with `User.Read` risky can add it.

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positive cases | Negatives | Recorded datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 5 of 5 matched (6 events) | 0 of 5 matched | 2 rows from 87 records, both attack |

Positives: the recorded 365-stealer user consent (its consent and grant
events, one case), the recorded OTRF tenant-wide `Mail.ReadWrite` grant,
and 3 hand-written (admin consent to `Files.ReadWrite.All`, a re-consent
adding `Mail.Send`, a lower-case scope). Negatives: 3 recorded (blocked
consent, role assignment grant, add service principal) and 2
hand-written (benign scopes only, `Mail.ReadBasic` only). Each negative
was shown to match when the clause it tests is removed. YARA-L and SPL
versions do not exist (Sentinel only).

## Blind spots
- Consent phishing that requests only `openid profile email` and uses
  the consent screen as a lure (Proofpoint, July 2025): no risky scope,
  so no alert, and the damage is done on the phishing page afterwards.
- Application (app-only) permissions granted to an app: that is
  `Add app role assignment to service principal`, covered by B2.
- Scopes outside the list (for example `Calendars.ReadWrite`,
  `Chat.Read`, `Tasks.ReadWrite`, third-party APIs); permissions on
  resources other than Graph and Exchange are not judged.
- Device code phishing and token theft without any consent (B3 covers
  part of the replay side).
- Consents in another tenant to which the user signs in as a guest.

## References
- Microsoft Threat Intelligence, "Threat actors misuse OAuth
  applications to automate financially driven attacks", 12 December
  2023,
  https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
  (fetched 2026-10-27).
- Proofpoint, "Microsoft OAuth App Impersonation Campaign Leads to MFA
  Phishing", 31 July 2025,
  https://www.proofpoint.com/us/blog/threat-insight/microsoft-oauth-app-impersonation-campaign-leads-mfa-phishing
  (fetched 2026-10-27).
- Microsoft Sentinel analytic rule `EndUserConsentMailboxOfflineAccess.yaml`
  (exact scope matching, consent-property names), Azure-Sentinel repo
  at commit c34840b, `Solutions/Microsoft Entra ID/Analytic Rules/`
  (read 2026-10-27).
- Sentinel `AuditLogs` columns: `schemas/reference/sentinel/AuditLogs.yaml`.
