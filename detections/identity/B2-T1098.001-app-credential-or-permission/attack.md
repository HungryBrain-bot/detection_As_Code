# Credential or high-risk permission added to an Entra app (T1098.001)

## What the attack is
An application or service principal in Entra ID can sign in on its own,
with a client secret, a certificate or a federated identity credential,
and act with whatever application permissions it holds. An attacker
who adds their own credential to an existing app, or grants an app they
control a powerful permission, gets access that survives the
compromised user's password reset and MFA change, and that runs as the
app rather than as a person.

## How the attack happens
1. The attacker controls a user who can manage the app: its owner, an
   Application or Cloud Application Administrator, or a Global
   Administrator (often after AiTM phishing or password spraying).
2. They add a credential to an app that already has useful permissions:
   - a client secret or certificate (`az ad app credential reset
     --append`, `New-MgApplicationPassword`, the portal's
     "Certificates & secrets"), or the same on the service principal
     (`Add service principal credentials`);
   - or a federated identity credential that trusts tokens from an
     outside issuer, for example a GitHub Actions workflow in a
     repository the attacker owns. No secret is stored at all.
3. Or they create or choose an app and grant it application permissions
   (admin consent to `Mail.ReadWrite`, `full_access_as_app`,
   `RoleManagement.ReadWrite.Directory` ...), written as
   `Add app role assignment to service principal`.
4. They sign in as the app (client credentials flow) from their own
   infrastructure and read mail, change the directory, or come back
   after the user account is cleaned up.
5. The recorded OTRF intrusion (SimuLand Golden SAML) adds secret
   `SimuLandCreds` to `SimuLandApp` with PowerShell, after granting it
   `Mail.ReadWrite`.

## Real-world use
- Microsoft Threat Intelligence, "Threat actors misuse OAuth
  applications to automate financially driven attacks" (12 December
  2023): in the cases Microsoft describes, actors added credentials to
  OAuth apps from compromised accounts. Microsoft writes that the actor
  "operated under the compromised user account session to add new
  credentials to the OAuth application", and that the cryptomining
  actor (Storm-1283) would "add a set of secrets to the application". Its hunting queries look for
  `Update application – Certificates and secrets management`.
- MITRE ATT&CK v20.0, T1098.001 (Additional Cloud Credentials): "adversaries may
  add credentials for Service Principals and Applications in addition
  to existing legitimate credentials in Azure / Entra ID", citing
  Microsoft's SolarWinds customer guidance (STIX bundle read
  2026-10-27).
- Splunk's attack_data includes a federated identity credential that
  trusts an outside GitHub repository (dataset dated 2026-06-10); it is
  a lab simulation, not a report of an intrusion.

## What it leaves in the logs
Entra ID audit log (`AuditLogs`), category `ApplicationManagement`:
- `Update application – Certificates and secrets management` (with an
  en dash; recorded with a trailing space) or
  `Add service principal credentials`: `modifiedProperties`
  `KeyDescription`, old and new lists of
  `[KeyIdentifier=...,KeyType=Password|AsymmetricX509Cert,KeyUsage=Verify,DisplayName=...]`.
  The secret value is never logged.
- `Update application` / `Update service principal` with
  `FederatedIdentityCredentials`: the new value lists issuer, subject
  and audiences.
- `Add app role assignment to service principal`: the target is the
  resource (for example Microsoft Graph), with `AppRole.Value` (the
  permission name) and `ServicePrincipal.DisplayName` (the app that
  received it).
- `InitiatedBy` names the user or app that made the change, with IP.
- The app's later sign-ins are in `AADServicePrincipalSignInLogs`
  (not loaded here).
The attacker chooses the credential's display name (it can mimic an
existing one) and cannot suppress the audit event.

## Prerequisites
Ownership of the app, or a directory role that can manage applications
or grant admin consent. Usually preceded by a compromised account
(T1078.004) and, for app permissions, by an existing app (T1136.003
when the attacker creates one).

## Mapping
T1098.001 Additional Cloud Credentials, tactic persistence (ATT&CK
also lists privilege-escalation). Adding a secret, certificate or
federated credential is the technique's own example. Granting a
high-risk application permission is closer to T1098.003 (Additional
Cloud Roles) in spirit, but ATT&CK scopes T1098.003 to roles and
groups; the rule maps only T1098.001 and the permission branch is
documented as part of the same persistence step (an app the attacker
can authenticate as, with the access they need). Not T1528: no user
token is involved.

## References
- Microsoft Threat Intelligence, "Threat actors misuse OAuth
  applications to automate financially driven attacks", 12 December
  2023,
  https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
  (fetched 2026-10-27).
- MITRE ATT&CK T1098.001, https://attack.mitre.org/techniques/T1098/001/
  (STIX bundle v20.0 read 2026-10-27).
- Microsoft Sentinel analytic rules `NewAppOrServicePrincipalCredential.yaml`
  and `AzureADRoleManagementPermissionGrant.yaml`, Azure-Sentinel repo at
  commit c34840b, `Solutions/Microsoft Entra ID/Analytic Rules/`
  (read 2026-10-27).
- Splunk attack_data, T1098.001/azure_ad_service_principal_credentials
  and azure_ad_federated_identity_credential, commit b52ee68,
  https://github.com/splunk/attack_data (fetched 2026-10-27).
- OTRF Security-Datasets, compound/GoldenSAMLADFSMailAccess, commit
  d9d40ef, https://github.com/OTRF/Security-Datasets (fetched 2026-10-27).
