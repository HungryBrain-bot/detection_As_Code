# EC2 shell opened through AWS by an identity outside the admin list

ATT&CK: T1021.008 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

AWS counterpart of [E8](../E8-T1078.004-app-service-publishing-login/)
(ADR 014). E8 watches App Service's back door (Kudu, FTP, Web Deploy);
this rule watches EC2's: shells opened through the AWS API.

## Hypothesis
On AWS, an identity with the right IAM permissions can get a shell on
an instance without a network path or an SSH key of its own: Systems
Manager Session Manager (`StartSession`), EC2 Instance Connect
(`SendSSHPublicKey` pushes a key for 60 seconds) and the EC2 serial
console (`SendSerialConsoleSSHPublicKey`). An attacker with a stolen
role or user uses them to move from the cloud control plane onto a
server. In most accounts only a few people and roles should ever do
this; anyone else is worth a look.

## Data sources
- `aws-cloudtrail` (cloud platform team): `AWSCloudTrail`. AWS: Systems
  Manager calls including `StartSession` "generate entries in the
  CloudTrail log files" as management events; Instance Connect
  connections show as `SendSSHPublicKey` events from
  `ec2-instance-connect.amazonaws.com`.
- Per customer: `admin_identities`, the role and user ARNs allowed to
  open shells (role ARN, not session ARN). Empty means every opening
  alerts, which is right for accounts where no one should.

## Detection logic
Query in [rule.yaml](rule.yaml).
1. `ssm:StartSession`, `ec2-instance-connect:SendSSHPublicKey` and
   `SendSerialConsoleSSHPublicKey` events, any result (a denied call is
   an attempt).
2. Identity = the session issuer (role) ARN for assumed roles, else the
   caller ARN, lower case; drop identities on the admin list.
3. Target instance: the first `i-` / `mi-` id anywhere in the request
   (key names differ between AWS's example and the recorded events:
   `instanceId` / `instanceOSUser` recorded, `instanceId` / `osUser` in
   AWS's user guide example). OS user and SSM document reported when
   present.
4. One row per identity and account per run, with operations, targets,
   OS users, documents, error codes, addresses, user agents, regions.

## Why this logic
- These three operations, not SSM in general: `ResumeSession`,
  `TerminateSession`, `SendCommand` (patching and automation),
  `DescribeInstanceInformation`, serial console status checks and
  `ImportKeyPair` are not a shell being opened. Matching any SSM, EC2
  or Instance Connect call made two negatives match; matching every SSM
  operation ending in `Session` made `ResumeSession` match.
- `SendCommand` is left out on purpose: it runs commands too, but it is
  the patching and automation path in most accounts, and alerting on it
  needs a different allow list (parked).
- Role, not session: role sessions get a new ARN each time (as B16 and
  B17 do, ADR 013).
- Any result: the recorded data has only successes; a denied attempt by
  an unexpected identity is still worth seeing.
- One row per identity: the recorded set is 12 key pushes in 14 seconds
  by one role, one alert.

## False positives
- Administrators and on-call roles not yet on the list. Fill the list
  before enabling; review the first week's alerts to complete it.
- Break-glass roles used in an incident.
- Port forwarding to databases through Session Manager by developers
  (`AWS-StartPortForwardingSession`), where that is the normal path.

## Tuning
- Negatives tested (6): `ResumeSession`, `TerminateSession`,
  `SendCommand` by patch automation, `DescribeInstanceInformation`,
  `GetSerialConsoleAccessStatus`, `ImportKeyPair`. Two loosenings made a
  negative match (evidence). Filling `admin_identities` with the three
  positive identities and the recorded role returned 0 rows, so the
  list works as an exclusion.
- Severity: raise to High for production accounts where no one should
  open shells.

## Test evidence
Run on 2026-11-21 in the Kusto emulator; [tests/evidence.md](tests/evidence.md).
3 of 3 hand-written positive cases matched, 0 of 6 negative cases. The
recorded Instance Connect set (Splunk attack_data, 12 `SendSSHPublicKey`
calls by one role, 2026-09-23) returned 1 row with the role, instance
and OS user `ec2-user`.

## Blind spots
- What happens inside the session: Session Manager session logs (S3 /
  CloudWatch) and the instance's own logs are not read.
- Shells opened without the AWS API: plain SSH with an existing key,
  RDP, a web shell (E2-E4 cover web-server shells where an endpoint
  sensor runs).
- `ssm:SendCommand` and `ssm:StartAutomationExecution` used as a shell
  (left out above).
- That `SendSerialConsoleSSHPublicKey` is written to CloudTrail was not
  found on a fetched AWS page; it is an operation of the same Instance
  Connect API (API reference, fetched) and is matched if it is logged.
- The `requestParameters` key names for `StartSession` were not found
  in a fetched CloudTrail example; the rule does not depend on them.
- An attacker who uses an identity on the admin list.

## References
- AWS, "Logging AWS Systems Manager API calls with AWS CloudTrail"
  ("calls to the `CreateMaintenanceWindows`, `PutInventory`,
  `SendCommand`, and `StartSession` actions generate entries in the
  CloudTrail log files"),
  https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html
- AWS, StartSession API reference (`Target`, `DocumentName`, `Reason`),
  https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_StartSession.html
- AWS, EC2 Instance Connect API reference, `SendSSHPublicKey`
  (`InstanceId`, `InstanceOSUser`, `SSHPublicKey`) and
  `SendSerialConsoleSSHPublicKey` (`InstanceId`, `SerialPort`,
  `SSHPublicKey`),
  https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.html,
  https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSerialConsoleSSHPublicKey.html
- AWS, "Log Amazon EC2 API calls using AWS CloudTrail", section "Audit
  connections made using EC2 Instance Connect",
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitor-with-cloudtrail.html
- Splunk attack_data b52ee68, `T1021.008/aws_ec2_multiple_ssh_public_keys_uploaded` (Apache-2.0).
AWS pages fetched 2026-11-21 through a fetch tool.
