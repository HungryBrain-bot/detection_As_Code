# Credential, federated credential or high-risk application permission added to an app

ATT&CK: T1098.001 · Severity: Medium · Status: test · Tier: baseline · Targets: sentinel

## Hypothesis
If an attacker adds a way to authenticate as an app, or gives an app a
powerful application permission, the Entra audit log will show a
successful change whose new `KeyDescription` or
`FederatedIdentityCredentials` list has an entry the old one lacks, or
an `Add app role assignment to service principal` for a permission on a
short high-risk list.

## Data sources
- Log source `entra-audit` (owner: identity team): Sentinel `AuditLogs`.
- Fields: `OperationName`, `Result`, `TargetResources`
  (`modifiedProperties` old and new values), `InitiatedBy`,
  `CorrelationId`, `TimeGenerated`.
- Tier baseline: same reasoning as B1, `AuditLogs` is the same table in
  every tenant that sends Entra audit logs; the gate's probe still has
  to confirm it per customer.

## Detection logic
Full query in `rule.yaml`. In order:
1. Successful `... Certificates and secrets management`,
   `Add service principal credentials`, `Update application`,
   `Update service principal` or
   `Add app role assignment to service principal`. The first is matched
   with `has`, because the recorded operation name has an en dash and a
   trailing space.
2. For each target, the modified properties are folded into one bag of
   new values and one of old values.
3. Credential added: `set_difference(new KeyDescription, old
   KeyDescription)` is not empty, that is, a key identifier exists that
   was not there before. Removing or keeping keys gives an empty
   difference.
4. Federated credential added: the same difference on
   `FederatedIdentityCredentials`.
5. Permission granted: `AppRole.Value` of an app role assignment, lower
   case, is one of 16 high-risk Graph / Exchange application
   permissions (mail, files, sites, users, groups, directory write,
   application and app-role management, role management).
6. One row per change, naming what was added, to which object, by whom
   and from which IP.

## Why this logic
- Alternative 1, any audit event in "Certificates and secrets
  management": also fires when a secret is deleted or expires out of the
  list. Comparing old and new key lists alerts only on additions.
- Alternative 2, Microsoft's `NewAppOrServicePrincipalCredential` rule:
  it skips objects whose old key list was empty (`old_value_set !=
  "[]"`), leaving first credentials to a separate "rare user" rule. That
  would miss both recorded attacks here (SimuLand and Splunk each add
  the first secret). This rule alerts on first credentials too and
  accepts the extra volume from new app registrations.
- Alternative 3, alert on `RequiredResourceAccess` changes (permissions
  added to the app's manifest): that is a request, granted only when
  someone consents; the grant itself is the
  `Add app role assignment to service principal` event this rule reads.
  Both recorded manifest changes are negatives.
- Alternative 4, the app's service principal sign-ins from new IPs:
  needs `AADServicePrincipalSignInLogs` and a baseline; a later rule.

## False positives
- Developers and pipelines adding or rotating secrets and certificates
  on their own app registrations: the main source of volume. Rotation
  adds a new key before the old one is removed, so it alerts.
- Workload identity federation set up legitimately for CI/CD (GitHub
  Actions, Azure DevOps, Kubernetes).
- Admins granting application permissions during onboarding of backup,
  e-discovery or mail-migration tools.

## Tuning
- Recorded data showed the operation name with an en dash and a
  trailing space; matching it with `has "Certificates and secrets
  management"` instead of `==` is required, and tested on two recorded
  events.
- First tuning step per customer: allowlist the service accounts and
  automation identities that rotate credentials (`InitiatedBy`), and the
  federated issuers and subjects the customer uses (for example their
  own GitHub organisation in `subject`).
- Raising severity when the initiator is a user who has not managed the
  app before needs a lookup of past audit events; left to customers that
  want it.

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positive cases | Negatives | Recorded datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 5 of 5 matched | 0 of 6 matched | 4 rows from 87 records, all attack or lab test (one OTRF row is exported twice) |

Positives: 3 recorded (SimuLand secret, Splunk secret, federated
credential) and 2 hand-written (a certificate added to a service
principal that already had a secret, an app role assignment of
`Mail.ReadWrite`). Negatives: 3 recorded (service principal rename, two
manifest changes) and 3 hand-written (credential removed, low-risk app
role `User.Read.All`, failed add). Each negative was shown to match
when the clause it tests is removed. The app-permission branch rests on
hand-written samples only.

## Blind spots
- Credentials added through an API path that writes different
  operation names or properties: only the recorded shapes and the
  operation names Microsoft's own rule lists are tested; other paths
  were not checked.
- Application permissions outside the list, and permissions on APIs
  other than Graph and Exchange.
- Delegated permissions: B1.
- An attacker who uses an app's existing credential (stolen from a
  pipeline or key vault) adds nothing and is not seen.
- New app registrations with the attacker's credential from creation
  are only seen if the credential is added as a separate event.

## References
- Microsoft Threat Intelligence, "Threat actors misuse OAuth
  applications to automate financially driven attacks", 12 December
  2023,
  https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
  (fetched 2026-10-27).
- Microsoft Sentinel analytic rules `NewAppOrServicePrincipalCredential.yaml`
  and `AzureADRoleManagementPermissionGrant.yaml`, Azure-Sentinel repo at
  commit c34840b (read 2026-10-27).
- MITRE ATT&CK T1098.001 (STIX bundle v20.0 read 2026-10-27).
- Sentinel `AuditLogs` columns: `schemas/reference/sentinel/AuditLogs.yaml`.
