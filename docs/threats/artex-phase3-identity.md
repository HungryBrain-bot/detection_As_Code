# ARTEX-style agentic attacks, Phase 3: identity

Written 2026-11-07 for the owner's blog series. Phase 3 is how an agent
works through every way into a login: password spraying, OAuth callback
and `state` tampering, unsigned JWTs, account-recovery abuse and probing
of SSO and Microsoft 365 endpoints. Phase 1 (credential sourcing) is in
[artex-phase1-credential-sourcing.md](artex-phase1-credential-sourcing.md),
Phase 2 (recon) in [artex-phase2-recon.md](artex-phase2-recon.md). This
file maps each place the blog draft suggests a detection to what was
built, records which of the draft's factual claims the sources support,
gives corrected wording where they do not, and keeps the hardening
guidance. Later phases are not covered.

## What was built

| Blog draft says | Built | Type |
|---|---|---|
| Many accounts failing with the wrong password (50126) in a short window, from many IPs each making few attempts; the same accounts re-targeted in later rounds. Entra `SigninLogs` (50126, 50053) | [B8](../../detections/identity/B8-T1110.003-entra-account-side-spray/) (counted per account, not per IP; IP count reported, not required) | Rule, T1110.003 |
| Same, Okta System Log (`user.session.start` failures) | [B9](../../detections/identity/B9-T1110.003-okta-account-side-spray/) (`OktaSSO` table; lockouts counted too) | Rule, T1110.003 |
| One client fingerprint, session or IP range doing two or more of: failed sign-ins across accounts, OAuth `state` / `redirect_uri` tampering, rejected JWTs, password resets for several users, legacy / alternative auth endpoints, within about 30 minutes | [B10](../../detections/identity/B10-T1110.003-one-client-many-login-flows/) for the three behaviours Entra logs record (key: source /24 or /64); the two application behaviours are in B13 | Rule, T1110.003 + T1589 |
| Recovery abuse: Entra `AuditLogs` (SSPR activity), Okta `user.account.reset_password` | [B11](../../detections/identity/B11-T1589-recovery-for-many-users/) for Entra. **Okta not built**: see the claims table | Rule, T1589 |
| Legacy auth probing: `SigninLogs` filtered on `ClientAppUsed` for legacy protocols (`/autodiscover`, `/EWS`, ROPC) | [B12](../../detections/identity/B12-T1110.003-legacy-auth-probing/) (legacy client names, plus `AuthenticationProtocol` "ropc", which `ClientAppUsed` alone misses) | Rule, T1110.003 + T1078.004 |
| OAuth / JWT tampering from application, API gateway and WAF logs, "often not collected, so check before writing the rule" | [B13](../../detections/identity/B13-T1606-oauth-jwt-tampering/), **schema-dependent**: reads `AppAuthEvent_CL`, a table this project defines; it exists only if the app writes it | Rule, T1606 + T1190 |
| Hardening: reject `alg: none` in CI, exact `redirect_uri`, `state` validation, per-account recovery rate limit, block legacy auth, phishing-resistant MFA, Smart Lockout / ThreatInsight on | Guidance below | Not rules |

All six are `status: test`, `targeted`, Sentinel only, and pass in the
Kusto emulator. B8 also ran on two recorded Entra sprays (both caught)
and B12 on recorded MFASweep ROPC sign-ins (caught); B9 ran on the only
recorded Okta data (10 accounts, below its threshold, not caught). B10,
B11 and B13 rest on hand-written samples only. Every threshold is this
project's choice. Design decisions are in
[ADR 011](../decisions/011-identity-attack-rules.md).

Why the ATT&CK IDs (enterprise bundle, mitre/cti master, fetched
2026-11-07; none revoked or deprecated): T1110.003 Password Spraying for
B8, B9, B12 and B10's failure leg; T1589 Gather Victim Identity
Information for B11 and B10's reset leg, because ATT&CK's own text covers
"probing and analyzing responses from authentication services that may
reveal valid usernames" and cites an SSPR-abuse write-up; T1078.004 for
B12's accepted-password branch; T1606 Forge Web Credentials for an
unsigned JWT ("credentials are new and forged by the adversary") and
T1190 for exploiting an app that skips `state` or signature checks.
Not used: T1556 Modify Authentication Process (changing the
authentication mechanism, which nothing here sees), T1550 (stolen
alternate material, not forged), T1087.004 (needs authenticated access),
T1110.004 credential stuffing (no source says the passwords were leaked
ones).

## Claims in the draft, checked against sources (2026-11-07)

Sources fetched: the Wiz post (read in full), Microsoft's 2026-10-21
Storm-0940 report (read in full in two fetches), Microsoft Learn (Entra
error codes, Smart Lockout, SigninLogs table reference, ROPC,
Conditional Access client apps, legacy-authentication workbook, SSPR
reporting, audit activity reference), Okta developer and help pages
(System Log event types, ThreatInsight), Azure API Management docs, and
Microsoft's Azure-Sentinel repository at commit c0c2dc2. All web pages
came through a fetch tool, so quotes were not checked character by
character.

| Claim in the draft | Status | Source and what it says |
|---|---|---|
| "Wiz observed the Storm-0940-overlap cluster" | **Partly; reword** | Wiz: "Our observations overlap with Microsoft's recent report on Storm-0940, a Chinese-state aligned actor"; Wiz describes "an actor using tooling associated with ARTEX". "Cluster" is not Wiz's word. Suggested: "Wiz observed an ARTEX-using actor whose activity overlaps with Microsoft's Storm-0940 report" |
| It password-sprayed Okta and Entra ID | **Supported** | Wiz playbook: "Password-spray corporate Okta and Entra ID environments"; "The activity was IDP-agnostic, hitting both Entra and Okta". Microsoft: Storm-0940 infrastructure "conducted an automated cross-tenant password-spray campaign targeting 327 accounts across eight organizations" |
| It tampered with OAuth callback and `state` parameters | **Supported** | Wiz: "manipulate OAuth callbacks and state parameters"; "the agent directly manipulated the callback endpoint by injecting fabricated authorization codes and malformed state parameters"; log line `GET /sign_in/oauth/microsoft/callback?code=AAAA&state=notvalidb64!!`. `redirect_uri` is **not** in the Wiz post; exact-match `redirect_uri` is sound guidance, not an observed technique |
| It submitted unsigned JWTs to see whether the app would accept them | **Supported** | Wiz: "test unsigned JWTs"; the example token "decodes to `{"alg":"none"}` and `{"email":"test@test.com"}`"; "Although most of these attempts failed, the true threat lies in the methodology." Wiz does not report any app accepting one |
| It probed SSO and Microsoft 365 endpoints | **Supported as worded; the draft's examples are not** | Wiz: "probe SSO and Microsoft 365-specific endpoints"; "bombarded more than 60 variations of SSO routes with this payload in just two minutes". `/autodiscover`, `/EWS`, ROPC and legacy authentication are in neither the Wiz post nor Microsoft's report. Present them as typical endpoints to watch, not as what Wiz saw. The only user-enumeration example in Wiz is app-level (`GET /Account/ValidateUserName?UserName=admin`) |
| ARTEX chains existing techniques: worker agents try each technique against each flow, record what fails, and adjust | **Partly** | Wiz: "When a login page started rate-limiting the activity, the agent simply switched to a different endpoint on the same host and carried on"; "Adaptation was automatic"; "Steps were chained automatically"; ARTEX's "worker agents run tools like `nmap`, `curl`, and `Impacket`, and every result feeds a shared graph of assets and findings". Wiz does not say the agent records failures per technique or tries each technique on each flow |
| Account-recovery abuse (guessable answers, enumeration, no rate limit) | **Supported for app and Cognito flows; not shown for Entra SSPR or Okta** | Wiz playbook: "Abuse account recovery: Repeatedly invoke password-reset, username-recovery, activation, and reset-token endpoints"; log `POST /api/v1/Users/GeneratePasswordResetToken → 204`, `POST /forgot_password`; Cognito `ForgotPassword`. Microsoft's report has no password reset. "Guessable answers" is the draft's own example |
| "It can spread across IPs, but not across accounts"; spraying shows "from many IPs that each make only a few attempts" | **Partly; the per-IP half is not what the sources show** | Wiz: "Rotate IP addresses when blocked"; "when IPs were blocked, new addresses appeared within minutes"; three of Wiz's five IOC addresses are in one /24 (144.172.64.60, .99, .128). Microsoft's spray came from "Storm-0940 infrastructure at 144.172.64[.]99", "151,000+ failed logon events", "peaking on October 11 at 2,900 failures per minute", 48 accounts over 1,000 failures, lockout responses "nearly 98%". That is high volume from known infrastructure, not few attempts per IP. The account-side argument holds either way; B8 and B9 do not require many IPs. Suggested: "It rotates IPs when it gets blocked, so per-IP limits slow it down only briefly. It still has to target your users, and that shows up from the account side" |
| The same accounts are targeted again in later rounds | **Supported in substance** | Wiz: "Some individual users were subjected to more than a dozen login attempts"; "Individual bursts lasted anywhere from 20 to 60 minutes"; "Some sessions lasted 24–30 hours". Microsoft: 48 accounts with over 1,000 failures. "Rounds" is the draft's term; B8's one-hour rounds are this project's |
| Entra `ResultType 50126`, `50053` | **Supported as the right codes** | Microsoft Learn: 50126 "Error validating credentials due to invalid username or password", "Expect to see some number of these errors in your logs due to users making mistakes"; 50053 "The account is locked because the user tried to sign in too many times..." and also used when "sign-in was blocked because it came from an IP address with malicious activity". Neither code is in Wiz or Microsoft's report. That Microsoft's "lockout responses" were 50053 is an inference |
| "Entra Smart Lockout and Okta ThreatInsight work at account and tenant level ... They don't depend on the attacker's IPs." | **Wrong for ThreatInsight, imprecise for Smart Lockout** | Smart Lockout: "10 failed attempts" by default in public cloud, first lockout "one minute", and "uses familiar location versus unfamiliar location", with "separate lockout counters". ThreatInsight: "It analyzes data to identify potentially suspicious IP addresses"; "Blocked requests aren't treated as failed user sign-in attempts"; its `security.threat.detected` events "don't include a username". Suggested: "Keep Entra Smart Lockout on: it counts per account, so rotating IPs does not reset it. Keep Okta ThreatInsight on too, but know it works the other way, by rating source IPs, so fresh IPs get past it and the requests it blocks never reach your failed-sign-in counts" |
| Recovery abuse: Okta `user.account.reset_password` | **Not verified; possibly wrong** | The Okta event catalog section with `user.*` events could not be read (the fetch returned only the first part of a 1,206-entry page). Microsoft's own Okta hunting query (Azure-Sentinel c0c2dc2, `UserPasswordReset.yaml`) reads `user.account.reset_password` as "admin attempts to reset user passwords". If so, it does not record self-service recovery by an outsider. No Okta branch built; check Okta's catalog before naming the event in the post |
| Recovery abuse: Entra `AuditLogs` SSPR activity | **Supported** | Microsoft Learn SSPR reporting lists "Self-service password reset flow activity progress", "Reset password (self-service)", "Blocked from self-service password reset" and others; "Blocked..." means the user tried "more than five total times in 24 hours". Not verified: that SSPR audit records carry the initiator's IP (B10 and B11 need it; no recorded SSPR event was available). The same page says "You must opt in for this data to be gathered on behalf of your organization"; whether that applies to the audit events was not established |
| Legacy auth probing: `SigninLogs` on `ClientAppUsed` | **Partly; ROPC is missed this way** | Microsoft does not publish the value list. Microsoft Learn: modern clients show as "browser" or "modern mobile/desktop client", "If it has a specific client or protocol name, such as "Exchange ActiveSync," it's using legacy authentication." ROPC shows in `AuthenticationProtocol` ("none, oAuth2, ropc, wsFederation, saml20, deviceCode", SigninLogs reference). Recorded MFASweep ROPC sign-ins (Splunk attack_data) have `ClientAppUsed` "Mobile Apps and Desktop clients" and `AuthenticationProtocol` "ropc"; a `ClientAppUsed` filter skips them. Also, a request to `/autodiscover` or `/EWS` that never authenticates is not in `SigninLogs`. Suggested: "`SigninLogs` with a legacy `ClientAppUsed` or `AuthenticationProtocol == "ropc"`" |
| Unsigned JWTs and loose `state` checks are bugs in your code, not IdP attacks | **Consistent with the sources** | Wiz reports the attempts against apps' own callbacks and SSO routes, and that most failed. It is the draft's framing |
| OAuth / JWT tampering in app, API gateway and WAF logs, often not collected | **Supported, and narrower than the draft says** | Azure API Management's validate-jwt policy has predefined errors with Source `validate-jwt` (TokenNotPresent, TokenSignatureInvalid, TokenExpired, JwtInvalid ...) and `require-signed-tokens` defaults to true; `ApiManagementGatewayLogs` has `LastErrorSource` / `LastErrorReason`. Microsoft does not say the reasons appear there, and APIM logs no `alg`. No vendor log found records a failed `state` check. So for most apps the data has to be written by the app itself, which is what B13's table assumes |
| Wiz lists existing detection rules | Supported | Wiz: "Numerous Failed Login Attempts To Multiple Users Followed By A Successful Login To Admin User", "Potential Password Spray Attack From Single IP", "Okta Users Password Spray"; Wiz does not say which product they belong to |
| "No real user does that" (one client, several flows) | **Inference** | No source compares user and agent flows. A shared egress (office NAT, VPN, a proxy) puts many users behind one /24, which is B10's main false positive |
| Spray outcome | Supported | Microsoft: "Despite the scale, no successful authentication, token issuance, Graph call, or directory change was observed." Worth saying in the post: the documented spray failed |

## Hardening guidance (the draft's, not rules)

Standard practice; none of the fetched sources measures whether it stops
ARTEX. Wiz lists no hardening controls; Microsoft's report lists
application and audit reviews, not these.

- **Reject unsigned and `alg: none` JWTs in every API, and test it in CI.** Pin the accepted algorithms in the validator rather than reading `alg` from the token; add a test that sends a token with header `{"alg":"none"}` and expects 401. In Azure API Management, `validate-jwt` has `require-signed-tokens` (default true); check nobody turned it off. Where a rejection is logged, write `JwtAlg` so B13 can see it.
- **Exact `redirect_uri` match and `state` on every OAuth flow.** Register full redirect URIs, compare them as strings (no prefix or wildcard match), bind `state` to the browser session and reject a missing or replayed one. Log each rejection (B13's `oauth_redirect_rejected`, `oauth_state_mismatch`).
- **Rate-limit account recovery per account, not only per IP, and answer the same whether or not the account exists.** Entra SSPR already throttles a user after "more than five total times in 24 hours"; custom reset endpoints (Wiz's `GeneratePasswordResetToken`, `/forgot_password`) need the same, and the same response for unknown users removes the enumeration signal.
- **Block legacy authentication and avoid ROPC.** Conditional Access: block "Exchange ActiveSync clients" and "Other clients". Microsoft on ROPC: "Microsoft recommends you do *not* use the ROPC flow; it's incompatible with multifactor authentication (MFA)". Blocking stops successes; attempts still log, which is what B12 counts.
- **Phishing-resistant MFA for privileged and vendor-support accounts.** Microsoft's Storm-0940 report is about a vendor compromise reaching downstream tenants; vendor-support accounts are the ones to do first.
- **Keep Smart Lockout and ThreatInsight on**, with the caveat in the claims table: Smart Lockout is per account (10 failures by default), ThreatInsight is IP reputation and its blocks do not appear as failed sign-ins.

## Not built, parked in BUILD_LOG.md
- An Okta branch for recovery abuse (event semantics unverified).
- An Okta leg for B10 (one rule per IdP, since the gate needs every source a rule reads).
- Correlating B10 and B13 per source network in a Sentinel incident: B13's table is a prerequisite most tenants lack, so it was kept out of B10.
- A feed from `ApiManagementGatewayLogs` (validate-jwt errors) into B13's table, or a rule on it directly: reason names are documented, their appearance in `LastErrorReason` is not.
- `OktaV2_CL` (Okta connector v2 table, different column names).
- AADSTS50034 (unknown account) as a spray signal: left out of B8 to match the draft's codes; a spray with a bad user list shows as 50034.

## Sources
- Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", 2026-10-22 (Sapir Federovsky, Rami McCarthy), https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors
- Microsoft Threat Intelligence and Microsoft Security Research, "AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise", 2026-10-21, https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
- Microsoft Learn: https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes ; https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout ; https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs ; https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions ; https://learn.microsoft.com/en-us/entra/identity/monitoring-health/workbook-legacy-authentication ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication ; https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-reporting ; https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities ; https://learn.microsoft.com/en-us/azure/api-management/validate-jwt-policy ; https://learn.microsoft.com/en-us/azure/api-management/api-management-error-handling-policies ; https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/apimanagementgatewaylogs
- Okta: https://developer.okta.com/docs/reference/api/event-types/ (partly read); https://help.okta.com/en-us/content/topics/security/threat-insight/about-threatinsight.htm ; https://help.okta.com/en-us/content/topics/security/threat-insight/configure-threatinsight-system-log.htm
- Azure-Sentinel repository, commit c0c2dc2: `.script/tests/KqlvalidationsTests/CustomTables/OktaSSO.json`; `Solutions/Okta Single Sign-On/Analytic Rules/PasswordSpray.yaml`, `Hunting Queries/UserPasswordReset.yaml`, `Hunting Queries/LegacyAuthentication.yaml`; `Hunting Queries/SigninLogs/PrivilegedAccountsUsingLegacyAuthentication.yaml`; `Solutions/Business Email Compromise - Financial Fraud/Hunting Queries/LegacyAuthAttempt.yaml`; `Detections/MultipleDataSources/MultiplePasswordresetsbyUser.yaml`.
- Splunk attack_data, commit b52ee68, T1110.003, T1110.001, T1110, T1078 and T1098 directories (Apache-2.0).
- MITRE ATT&CK enterprise bundle (mitre/cti master).
All fetched 2026-11-07.
