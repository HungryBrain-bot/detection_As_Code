# Illicit OAuth consent grant (T1528)

## What the attack is
The attacker registers an application (or uses one they control in
another tenant) and gets a user, or an admin, to consent to it. Consent
gives the app delegated permissions such as `Mail.Read`, and Entra then
issues the app access and refresh tokens for that user's data. The
attacker never needs the user's password or MFA again: the app reads
mail or files with its own token until the grant is revoked. Password
resets do not remove a consent grant.

## How the attack happens
1. The attacker registers a multi-tenant app with a convincing name and
   logo, and a redirect URI they control. Tools such as 365-stealer
   automate this and the token collection afterwards.
2. They send the victim a link to Microsoft's real authorize endpoint
   (`login.microsoftonline.com/.../oauth2/v2.0/authorize?client_id=...&scope=Mail.Read offline_access ...`).
   The sign-in and the consent screen are Microsoft's own pages, so URL
   and certificate checks pass.
3. The victim clicks Accept. Entra writes the consent and creates a
   delegated permission grant (`oauth2PermissionGrant`) for the app.
4. The authorization code goes to the attacker's redirect URI; they
   redeem it for tokens and call Microsoft Graph as the user
   (read and send mail, search files), refreshing the token with
   `offline_access`.
5. Variant: an attacker who already holds an admin account grants the
   permissions directly through Graph or PowerShell, with no consent
   screen at all, often tenant-wide (`ConsentType: AllPrincipals`).
   OTRF's simulated Golden SAML intrusion does exactly this,
   granting `Mail.ReadWrite` to an app it controls.

## Real-world use
- Microsoft Threat Intelligence, "Threat actors misuse OAuth
  applications to automate financially driven attacks" (12 December
  2023): after compromising accounts, "The threat actor then granted
  consent to the applications using the compromised accounts", and the
  applications "were set with permissions like email, profile, openid,
  Mail.Send, User.Read and Mail.Read".
- Proofpoint, "Microsoft OAuth App Impersonation Campaign Leads to MFA
  Phishing" (31 July 2025): apps impersonating iLSMART and Adobe
  requested only `openid email profile` style scopes, and "Whether a
  person clicked Cancel or Accept, the attack flow is the same": the
  consent screen was a lure for a credential-phishing page, not the
  attack itself. This rule does not detect that campaign (see the rule
  doc, Blind spots), and it is cited here because it is the current
  form of OAuth app abuse a defender is most likely to meet.
- MITRE ATT&CK v20.0, T1528 (Steal Application Access Token), lists
  OAuth consent phishing as a way to obtain tokens (STIX bundle read
  2026-10-27).

## What it leaves in the logs
Entra ID audit log (`AuditLogs` in Sentinel), category
`ApplicationManagement`, service `Core Directory`:
- `Consent to application`: target is the client app's service
  principal; `modifiedProperties` include
  `ConsentContext.IsAdminConsent`, `ConsentContext.OnBehalfOfAll` and
  `ConsentAction.Permissions`, whose new value lists each grant as
  `[..., ConsentType: Principal|AllPrincipals, Scope: Mail.Read ..., ...]`
  after a `=>`. `InitiatedBy.user` is the consenting user and IP.
- `Add delegated permission grant`: target is the resource (for example
  Microsoft Graph), with `DelegatedPermissionGrant.Scope` and
  `DelegatedPermissionGrant.ConsentType`. A consent through the prompt
  writes both events with one `CorrelationId`; a direct grant writes
  only this one.
- `Add service principal` (first use of a multi-tenant app in the
  tenant) and `Add app role assignment grant to user`.
- A blocked or declined consent: `Consent to application` with
  `Result` `failure` (Entra's risky-app block,
  `ConsentAction.Reason` "Risky application detected"), or only a sign-in
  with error 65004 when the user declines.
- The token use afterwards appears in sign-in logs for the app and in
  Graph activity / mailbox audit logs, not read by this rule.
The attacker controls the app name, publisher display name and the
scopes requested; they cannot suppress the audit events.

## Prerequisites
A user who will click Accept, and a tenant that lets users consent to
apps from unverified publishers for those scopes; or an account with a
role that can grant permissions (Application Administrator, Cloud
Application Administrator, Global Administrator) for the direct-grant
variant. Phishing (T1566.002) usually delivers the link.

## Mapping
T1528 Steal Application Access Token, tactic credential-access: the
grant is what lets the attacker's app obtain tokens for the victim's
data. Using those tokens afterwards is T1550.001 (Use Alternate
Authentication Material: Application Access Token), which this rule
does not see. Not T1098.003 (Additional Cloud Roles): no directory role
changes. Application (app-only) permission grants are B2's, not this
rule's.

## References
- Microsoft Threat Intelligence, "Threat actors misuse OAuth
  applications to automate financially driven attacks", 12 December
  2023,
  https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
  (fetched 2026-10-27).
- Proofpoint Threat Research, "Microsoft OAuth App Impersonation
  Campaign Leads to MFA Phishing", 31 July 2025,
  https://www.proofpoint.com/us/blog/threat-insight/microsoft-oauth-app-impersonation-campaign-leads-mfa-phishing
  (fetched 2026-10-27).
- MITRE ATT&CK T1528, https://attack.mitre.org/techniques/T1528/
  (STIX bundle v20.0 read 2026-10-27).
- Splunk attack_data, T1528/azure_ad_user_consent_granted (365-stealer
  consent simulation, 2023-10-27), commit b52ee68,
  https://github.com/splunk/attack_data (fetched 2026-10-27).
- OTRF Security-Datasets, compound/GoldenSAMLADFSMailAccess, commit
  d9d40ef, https://github.com/OTRF/Security-Datasets (fetched 2026-10-27).
