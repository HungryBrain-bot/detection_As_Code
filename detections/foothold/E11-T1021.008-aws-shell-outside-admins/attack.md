# Shell on an instance through the cloud control plane (T1021.008)

## What the attack is
With cloud credentials that carry the right permissions, an attacker
opens a shell on a virtual machine through the provider's API instead of
the network: AWS Systems Manager Session Manager, EC2 Instance Connect
or the EC2 serial console. No inbound port, VPN or SSH key of their own
is needed.

## How the attack happens
1. The attacker holds an IAM user's key or a role session (stolen,
   leaked, or reached from a compromised workload).
2. They list instances (`ec2:DescribeInstances`,
   `ssm:DescribeInstanceInformation`).
3. They open a session: `ssm start-session --target i-...`, or push a
   key with `ec2-instance-connect send-ssh-public-key` and SSH in within
   60 seconds, or push a key to the serial console.
4. From the shell they read instance credentials, files and secrets,
   or move on.

## Real-world use
- ATT&CK T1021.008 (enterprise bundle 20.1) names "AWS EC2 Instance
  Connect" and "AWS System Manager" among the cloud-native methods
  adversaries use to "log directly into accessible cloud hosted compute
  infrastructure".
- The Phase 4 sources (docs/threats/artex-phase4-foothold.md) describe
  web-application footholds, not cloud control-plane shells. **No
  fetched source shows ARTEX opening shells through AWS.** E11 is the
  AWS counterpart of E8 (a deployment back door used as a shell), not a
  port of an observed ARTEX step.

## What it leaves in the logs
`AWSCloudTrail`: `ssm.amazonaws.com` `StartSession`,
`ec2-instance-connect.amazonaws.com` `SendSSHPublicKey` /
`SendSerialConsoleSSHPublicKey`, with the caller, the target instance in
`RequestParameters`, `SourceIpAddress`, `UserAgent`, `ErrorCode`.

## Prerequisites
The instance is managed by SSM, or runs the Instance Connect package
with a reachable SSH port, or has the serial console enabled; the
caller has the IAM permission.

## Mapping
T1021.008 Remote Services: Direct Cloud VM Connections (lateral
movement). The Splunk recording used here is filed under the same ID.
ID checked with `python -m dac validate --attack-bundle` on 2026-11-21.

## References
- See README.md, References.
