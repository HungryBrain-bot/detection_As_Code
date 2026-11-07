# Cloud permission and infrastructure discovery by trial (T1580)

## What the attack is
With a stolen or leaked cloud credential, the attacker lists what exists
and what the identity may do. The cheapest way is to call every list,
describe and get API of every service and see which answer. The failed
calls are the signal.

## How the attack happens
1. Obtain a credential (access key, assumed role, token).
2. Call read APIs across services (`ec2:Describe*`, `s3:ListBuckets`, `iam:List*`, `rds:Describe*` ...), from a script or a tool: Pacu, enumerate-iam, ScoutSuite, CloudMapper, CloudSploit, or hand-written boto3 / aws-cli loops.
3. Keep the calls that succeed; the denials tell the attacker what is not available.
The recorded lab data below was made by two such tools run with limited rights.

## Real-world use
Microsoft (2026-10-21) reports Storm-0940 activity where "they enumerated cloud resources and read secrets at scale across multiple Azure Key Vaults", and names an alert titled `KV_AccountVolumeAccessDeniedAnomaly`; the page's statement about AWS permission enumeration was not found (the page was read verbatim only in part). Wiz (2026-10-22) names a detection rule "Unusual Mass Access Denied Activity" for the "relentless behavior" it describes, and lists `aws-cli` and `Boto3` user agents; it does not say that ARTEX called AWS APIs, and the words CloudTrail, AccessDenied and UnauthorizedOperation do not appear in it. Whether ARTEX-style agents do permission enumeration this way is therefore not shown by the sources fetched; see docs/threats/artex-phase2-recon.md. The behavior is documented for other tools: the Splunk attack_data sets used here are cloudsploit and cloudmapper runs (2021).

## What it leaves in the logs
CloudTrail records each call, including failed ones, with `errorCode` (AWS: "The AWS service error if the request returns an error"), `errorMessage` ("includes messages for authorization failures"), the principal ARN, source IP and user agent. Sentinel: `AWSCloudTrail` (`ErrorCode`, `EventSource`, `EventName`, `UserIdentityArn`, `SourceIpAddress`, `UserAgent`). An attacker with the right to stop logging can remove it; read events may be filtered out of a trail by configuration.

## Prerequisites
A valid AWS credential, from any earlier step (leaked keys, a stolen session).

## Mapping
T1580 Cloud Infrastructure Discovery (tactic discovery). T1526 Cloud Service Discovery was listed by the owner and not used: ATT&CK describes it as enumerating "the cloud services running on a system after gaining access", which the failed-call burst can also be, and the rule cannot tell the two apart; T1087.004 (Cloud Account) is about accounts. Checked against the ATT&CK enterprise bundle (mitre/cti master, fetched 2026-11-07).

## References
- Microsoft Threat Intelligence and Microsoft Security Research, "AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise", 2026-10-21, https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/ (fetched 2026-11-07; the page was read verbatim only for its first 39,865 of 63,314 characters)
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22, https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors (fetched 2026-11-07)
- Splunk attack_data (Apache-2.0), commit b52ee68, T1580 and T1526 directories (fetched 2026-11-07).
