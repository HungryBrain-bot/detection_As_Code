# H1. Search for your own leaked secrets before an attacker's agent does

A hunt and runbook, not a detection rule: it runs outside the SIEM, on
public code, and nothing in a customer's logs records an attacker
searching GitHub. Maps to the attacker's step T1593.003 (Search Open
Websites/Domains: Code Repositories, reconnaissance) and T1552.001
(Unsecured Credentials: Credentials In Files). Written 2026-11-07 for
the ARTEX Phase 1 (credential sourcing) work; see
docs/threats/artex-phase1-credential-sourcing.md.

## Why
Microsoft (2026-11-05) reports that the agentic framework's GitHub
queries "often included the name of a target organization, keywords for
secrets, a keyword linked to cloud services, or a keyword linked to
another AI service provider". The queries are predictable, so the
defender can run them first. Microsoft's post does **not** list
specific keywords; the ones below are this runbook's choice of common
Azure and AI variable names.

## When
- Once now, as a baseline.
- Monthly, and after any public incident involving the organisation's
  repos, contractors or open-source projects.
- Continuously, through secret scanning (step 4).

## Steps

### 1. Search public code for the organisation's name with secret keywords
Use GitHub code search (signed in; https://github.com/search?type=code),
and repeat on GitLab and Bitbucket if staff use them. Replace `ORG` with
each of: the organisation's name, its primary domain (`example.com`),
its Entra tenant domain (`example.onmicrosoft.com`), and its tenant id.

```
"ORG" client_secret
"ORG" AZURE_CLIENT_SECRET
"ORG" tenant_id
"ORG" AZURE_TENANT_ID
"ORG" AZURE_OPENAI
"ORG" AZURE_OPENAI_API_KEY
"ORG" OPENAI_API_KEY
"ORG" ANTHROPIC_API_KEY
"ORG" path:.env
"ORG" filename:.env
"ORG" "DefaultEndpointsProtocol=https;AccountName="
"ORG" "vault.azure.net"
```

The same from the command line with an authenticated GitHub CLI
(`gh auth login` first; results are rate limited):

```bash
ORG="example.com"
for term in client_secret AZURE_CLIENT_SECRET tenant_id AZURE_OPENAI OPENAI_API_KEY "path:.env"; do
  echo "== $term"
  gh search code "\"$ORG\" $term" --limit 50 --json repository,path,url \
    --jq '.[] | "\(.repository.nameWithOwner)  \(.path)  \(.url)"'
done
```

Record each hit (repo, path, commit, who owns it). Do not test a found
secret by signing in with it: that is an unauthorised use if it is not
the organisation's, and it pollutes the logs B4-B6 read.

### 2. Search the organisation's own repos, including history
- Public and private org repos: GitHub secret scanning alerts
  (Security tab), or a scanner over full history, e.g.
  `gitleaks detect --source . --log-opts="--all"` or
  `trufflehog git file://. --no-verification` (verification would sign in with each found secret). Deleted lines stay in
  history and in forks.
- CI logs, container images and package artefacts are as common a
  source as code; scan the artefact registry too.

### 3. For every real secret found: rotate, then investigate
1. **Rotate first.** Deleting the commit or making the repo private does
   not invalidate the secret; forks and clones keep it. In Entra: add a
   new client secret, deploy it, then delete the old one
   (`az ad app credential reset` or the portal).
2. Prefer removing the secret entirely: managed identities for Azure
   workloads, workload identity federation for CI (GitHub OIDC). Microsoft:
   "using managed identities for application authentication eliminates
   the possibility of secret exposure in code".
3. Look back at its use: run B5 and B6's queries over the full
   retention for that `AppId` / `ServicePrincipalCredentialKeyId`, and
   B7's Graph checks for its `AppId`; check Key Vault audit for the
   app's id. Sign-in errors AADSTS7000215 (invalid secret) followed by
   success are, per Microsoft, urgent.
4. If it was used from outside the app's own network: treat it as an
   incident (revoke, review what the app's permissions allowed, check
   for added credentials on other apps, rule B2).

### 4. Turn on prevention
- GitHub secret scanning and push protection on every org repo
  (Microsoft: "Push protection can also block supported secrets before
  they're pushed"); validity checks where available.
- Plant honeytokens (rule B4): a decoy app registration's secret in a
  place an attacker would find, plus decoy Key Vault secrets, registered
  in `Honeytoken_CL`.

## What this misses
- Secrets leaked under a name that does not mention the organisation
  (a contractor's personal repo with only a tenant id). Searching the
  tenant id and app ids helps; nothing finds them all.
- Paste sites, public buckets, chat exports and Docker Hub images.
- Secrets already found and used: this is prevention; B4-B7 are the
  detections.

## Record
Log each run (date, terms, hits, actions) in the customer's ticketing
system, not in this repo: a list of where an organisation's secrets
leaked is sensitive.

## References
- Microsoft, "Threat actors use agentic AI tooling to find and abuse
  exposed secrets", 2026-11-05,
  https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
  (fetched 2026-11-07 through a fetch tool).
- MITRE ATT&CK T1593.003, T1552.001: enterprise bundle, ATT&CK 20.1
  (fetched 2026-11-07).
