# Build Log

## 2026-10-27 - Plan and scope

- Plan agreed with the owner in the project thread: 10 rules in three
  tracks (4 endpoint, 3 identity/OAuth, 3 LLM app), about 3 weeks,
  every rule with an attack doc and a rule doc written as it is built.
- SIEM coverage decided: Sentinel (KQL) for all 10 rules; Splunk (SPL)
  and Google SecOps (YARA-L) for the 4 endpoint rules only. Reason: the
  identity and LLM rules use Entra and custom tables that would need
  invented field mappings on Splunk and SecOps.
- Noted for the record: Google SecOps uses YARA-L, not YARA.

## 2026-10-27 - Pipeline (no rules yet)

- Built the rule schema, `dac validate`, the `SiemAdapter` interface
  with Sentinel, Splunk and SecOps adapters, the log-source gate with
  file and SMTP notifiers, the CLI, and the GitHub Actions workflow.
  Decisions in ADRs 001-003.
- Gate design change while building: confirmations are per log source
  per SIEM (not per rule), with 90-day expiry, so one confirmation
  covers every rule on that source (ADR 003).
- Added a check that a doc section is not the template's text left
  unchanged, since "filled in" by copying the template would otherwise
  pass.
- Real vs. mocked: no live SIEM or SMTP. Adapter tests run against a
  fake transport with response bodies written from vendor docs
  (`tests/fixtures/api/README.md`). Dry-run is the only deploy that has
  happened.
- Verified: 59 tests pass; yamllint clean; `dac validate` against the
  live MITRE enterprise ATT&CK bundle passes on the fixture rule, and
  the planned rules' technique IDs (T1059.001, T1547.001, T1003.002,
  T1105, T1528, T1098.001, T1550.001) all exist and are not deprecated.
- The repo was empty, so `main` was started with a one-file initial
  commit to give the first PR a base.
- Next: day-1 checks (free Azure Data Explorer cluster, OTRF /
  EVTX-ATTACK-SAMPLES coverage for A1-A4, ATLAS IDs for C1-C3), then
  rule A1 end to end.

## 2026-10-27 - Customers, baseline tier, schema check, coverage

- Owner reviewed PR #1 (merged, CI green) and asked for: a schema-aware
  log-source check using the SIEM itself (e.g. the Sentinel app
  registration querying tables), SIEM-specific (tables vs. indexes vs.
  log types); per-customer ATT&CK / ATLAS coverage for management; and
  high-value rules on native tables pushed to every customer.
- Decided: per-customer folders with one fictional `demo` customer
  (owner chose this on the decision card); `tier: baseline | targeted`;
  baseline still passes the gate, but a passing read-only probe
  auto-confirms a source, so baseline needs no human step where probe
  credentials exist. ADRs 004-006, ADR 003 amended.
- Built: `required_fields` per SIEM block; reference schemas for
  Sentinel SecurityEvent, Syslog, CommonSecurityLog; read-only probes in
  all three adapters; `dac/schema_check.py`; gate rewritten per
  customer with probe auto-confirm and veto and SIEM-specific "your data
  may land elsewhere, send the schema" reminders; `dac/coverage.py`
  (ATT&CK layer, ATLAS layer, summary); CLI commands `customers`,
  `schema-check`, `coverage`; CI matrix per customer x SIEM with one
  GitHub Environment per customer; skills `schema-check` and
  `coverage-map`; component docs for both.
- Real vs. mocked / unverified:
  - No live probe or deploy has run. Probe tests use response bodies
    written from vendor docs. The SecOps UDM search endpoint and
    response shape are a guess at the v1alpha API.
  - SecurityEvent's field list came through a summarising web fetch
    (learn.microsoft.com is blocked from the build environment by
    direct download); not yet checked character by character.
    Syslog and CommonSecurityLog are verbatim from the Azure-Sentinel
    repo's KQL-validation table definitions, not the Microsoft page.
  - No Splunk or SecOps reference schemas yet.
  - Navigator layer loading untested; ATLAS layer `domain` is a guess.
- Parked for the owner (not in scope, not built): common baseline rules
  outside the agreed 10, such as brute-force sign-ins and privileged AD
  group changes. Adding any of them is a scope change.
- Tests: 96 passed; yamllint and pyflakes clean.
- Next: unchanged. Day-1 checks, then rule A1. The pipeline is frozen
  until A1-A4 exist.

## 2026-10-27 - Rules A1-A4, engine tests on recorded data

- Owner's go-ahead to build the rules. The owner cannot create ADX or
  Log Analytics, and asked for the rules to be checked against
  open-source sample logs instead of shipping as "not run" (ADR 007).
- Engines: the Azure Data Explorer emulator (Kustainer, Docker) for
  KQL, and Splunk Enterprise 10.6.1 in Docker for SPL. Docker Hub
  rate-limited the Splunk pull; the same image came from
  `mirror.gcr.io`. No YARA-L engine exists outside SecOps; YARA-L is not
  run and each evidence file says so. Both containers were started with
  their vendors' licence-acceptance flags for local test use.
- Data: OTRF Security-Datasets (MIT), six recorded runs at commit
  d9d40ef, 45,370 events in total, pinned by SHA-256 in
  `harness/datasets.yaml`. EVTX-ATTACK-SAMPLES was not used: it had no
  licence file when checked.
- Built `harness/` (fetch, mapping to SecurityEvent / Event /
  XmlWinEventLog, engine clients, run), CI job `engine-kusto`, offline
  tests, docs/components/engine-tests.md, ADR 007, Sentinel `Event`
  reference schema.
- Rules A1 (T1059.001), A2 (T1547.001), A3 (T1003.002), A4 (T1105),
  each with attack doc, rule doc, labelled samples, dataset list,
  results and evidence. Status `test`. A1/A3/A4 baseline on
  SecurityEvent 4688; A2 targeted (Sysmon), included for `demo`.
- Results, both engines: every positive matched, no negative matched,
  and across all 45,370 events the four rules returned 7 rows, all of
  them the recorded attack events. Each negative set was checked to
  fail when the filter it guards is removed.
- Tuning found by the recorded background: `ClipRenew.exe -e` (A1),
  Defender writing a Run key (A2), `reg export HKLM\SYSTEM\...`
  subkeys (A3), `certutil -store` (A4).
- Correction: `log_sources.yaml` listed `SysmonEvent` as a Sentinel
  table. It was not taken from a fetched Microsoft source; Microsoft's
  own Sysmon parser (Azure-Sentinel repo) reads Sysmon from the `Event`
  table, so the catalogue now says `Event`.
- Fix found by running the queries: `check_balanced` reported real,
  working KQL and YARA-L as unbalanced, because it did not know KQL
  verbatim strings or YARA-L backtick regexes. It now takes each
  language's string-literal rules; tests added.
- Real vs. mocked / unverified: emulated engines, not Log Analytics or
  Splunk with the Windows add-on; lab data, not production; Sentinel
  table columns from reference schemas that came through a summarising
  fetch (recorded fields with no column are dropped on load and listed
  in each result file); SecOps UDM field names (`registry_key`,
  `principal.process.file.full_path`) are from my reading of Google's
  UDM, not verified.
- Gate on `demo`: all four rules blocked (no confirmations, no probe
  credentials), as expected; coverage shows 0 of 4 active.
- Tests: 115 passed; yamllint and pyflakes clean; `dac validate`
  against ATT&CK v20.0 passes.
- Next: identity rules B1-B3. Needs recorded Entra data with a reuse
  licence; not yet checked.

## 2026-10-27 - Parked: RAG over the attack docs

- Owner asked to record, for the future, a RAG system with evaluation
  that answers attack and tactic questions from the attack docs (CLI /
  FastAPI), later also the rules per customer. Not built, not
  scheduled. Scope, evaluation-first approach and dependency in
  docs/future/rag-over-attack-docs.md: answers cite their source doc,
  an eval set (retrieval hit rate, groundedness) comes before code, and
  it waits until enough rules and attack docs exist.

## 2026-10-27 - Identity rules B1-B3 (Entra ID, Sentinel)

- Owner asked to build the identity rules and to put them in PR #4 with
  the RAG note.
- Data found (fetched 2026-10-27): Splunk attack_data (Apache 2.0),
  nine Entra ID datasets at commit b52ee68 (consent granted, declined
  and blocked; app secret added; federated credential added; Graph
  permission added to a manifest; Evilginx2 session cookie replay; two
  sign-in datasets), Azure Monitor diagnostic format, tenant details
  replaced by Splunk. OTRF Security-Datasets (MIT): the `AuditLogs`
  export of the simulated Golden SAML intrusion. Column names and types
  for the three Entra tables: Microsoft's Azure-Sentinel repo (MIT,
  `Sample Data/Tables/*/metadata.json` at c34840b), read with git, not
  through a summarising tool.
- Reports (fetched 2026-10-27): Proofpoint, OAuth app impersonation,
  31 July 2025; Microsoft Threat Intelligence, OAuth app misuse,
  12 December 2023; Microsoft Defender XDR session cookie theft alert
  playbook, last updated 2 July 2026. No 2025-2026 report naming a
  group was found for token replay; B3's attack doc says so.
- Built: harness support for raw and LFS files, the diagnostic-format
  mapping, typed Entra tables, `_case` positive cases; reference
  schemas for AuditLogs, SigninLogs, AADNonInteractiveUserSignInLogs;
  rules B1 (T1528), B2 (T1098.001), B3 (T1550.001 and T1550.004), each
  with attack doc, rule doc, labelled samples, results and evidence.
- Results (Kusto emulator): every positive case matched, no negative
  matched. Recorded data: B1 2 rows, B2 4 rows (one OTRF event exported
  twice), all attack or lab test; B3 0 rows because no recorded sign-in
  has a `SessionId`. Each negative was checked to match when the clause
  it tests is removed.
- Decisions to review (owner):
  - B3 maps T1550.004 as well as the scoped T1550.001: the AiTM cookie
    replay it targets is T1550.004 in ATT&CK v20.0. CLAUDE.md's Scope
    table now notes it.
  - B3 alerts on two countries in one session (Microsoft's playbook
    check). It misses same-country replay, including the recorded
    Splunk one (both IPs in one ASN and country); two ASNs is the
    documented, noisier alternative.
  - B1/B2 `tier: baseline` (AuditLogs is native; the gate still checks
    it per customer). B3 `tier: targeted` because its false-positive
    profile could not be measured; not added to `demo`'s include.
  - B2's app-permission branch and `Add service principal credentials`
    rest on hand-written samples; property names from Microsoft's own
    Sentinel rules.
- Real vs. unverified: ADX engine, not Log Analytics; lab tenants, not
  production; B3 positives hand-written; no live tenant checked that
  `SessionId` is filled.
- Tests: 127 passed; yamllint clean; `dac validate` against ATT&CK
  v20.0 passes; `python -m harness run --engine kusto` passes for all
  seven rules.

## 2026-10-27 - LLM detection practice and rules C1-C3

- Owner asked to build the remaining three scoped rules (C1-C3), mapped
  to both OWASP LLM lists and MITRE ATLAS, tested on the closest real
  data, and, because LLM apps have no common log format, to set up an
  LLM logging practice for every future LLM rule: which log sources to
  use, what telemetry each gives, how each is integrated, kept as a log
  inventory with its own skill, and documented.
- No public recorded LLM-application log exists in any format. The
  practice (ADR 008, docs/components/llm-telemetry.md, skill
  `llm-log-inventory`): one normalised table `LLMAppLog_CL` (one row per
  OpenTelemetry GenAI span, semconv commit e19717d, status Development,
  content opt-in), `LLMCanary_CL` for canaries, `llm_log_inventory.yaml`
  with eight sources (OTel GenAI, MCP server, API Management AI gateway,
  Bedrock invocation logs, Azure OpenAI diagnostics, Vertex AI, Defender
  for AI alerts, canary registry), per-customer `llm_apps.yaml`, rule
  field `llm_telemetry.populated`, and `python -m dac llm-inventory`.
  `dac validate` also checks ATLAS IDs against pinned atlas-data
  v2026.06 (commit 3259f38); CI downloads it by commit and SHA-256.
- OWASP Top 10 for LLM Applications 2026 confirmed final (commit
  9253e38) and renumbers risks; rules carry `owasp_llm_2025` and
  `owasp_llm_2026`.
- Data (licences checked at the pinned commits, all MIT): JailbreakHub
  prompts (1,405 jailbreak, 13,735 regular), AgentDojo runs of one model
  on the banking and slack suites (300 runs: 231 injected and reached,
  18 injection not reached, 51 benign), BIPIA email attacks (75 attack
  texts, 50 emails). Converters in `harness/llm_datasets.py`; the logs
  around the text (timestamps, ids, span layout) are built by this repo.
- Results (Kusto emulator):
  - C1: jailbreak prompts 329/1,405 (23.4%) caught; regular prompts
    256/13,735 (1.9%) alerted, of which 17 of 30 read by hand are
    jailbreaks the dataset labels regular; AgentDojo injected 231/231
    (in-sample: the addressed-to-model category was written after
    reading AgentDojo's attack text), not-reached 0/18, benign 0/51;
    BIPIA 0/75 attacks, 0/50 clean emails.
  - C2: 5 rows, all the registered secret leaving the app: both recorded
    AgentDojo exfiltrations plus three where the user asked for it. No
    dataset has a planted canary; the registry row is hand-written.
  - C3: 0 alerts on 300 recorded agent runs (max 16 calls, 10 identical
    repeats per run); all positives hand-written.
  - Every positive case matched, no negative matched; each hand-written
    negative matches when the clause it tests is removed.
- Decisions to review (owner):
  - C2 maps LLM07:2025 System Prompt Leakage (LLM08:2026) as well as the
    scoped LLM02, because a canary in the system prompt is that risk.
  - C1 drops direct prompts whose only category is `override`: it removed
    954 regular and 105 jailbreak alerts. Keeping them trades recall for
    a 10.6% alert rate on regular prompts.
  - C1's addressed-to-model category is tuned on AgentDojo, so its
    AgentDojo result is not a recall estimate.
  - Tensor Trust (prompt-injection game data) has no licence file in its
    data repository, so it was not used.
  - Gateway sources (API Management, Bedrock) need either a copy job into
    `LLMAppLog_CL` or an ASIM-style parser function; ADR 008 picks the
    table for now. Neither is built.
  - C3 thresholds (50 calls per hour floor, 3x the agent's 7-day p95, 20
    identical calls) are judgment calls, not measured.
  - Log source `llm-app-gateway` renamed `llm-app-log` (no confirmation
    referenced it); `llm-canary-registry` added.
- Real vs. unverified: research text, not production app logs; ADX
  engine, not Log Analytics; `LLMAppLog_CL` / `LLMCanary_CL` never
  created in a workspace; every normaliser and the registry job are
  designs; inventory entries for Vertex AI and Azure OpenAI fields are
  not verified; scheduled-rule lookback limiting `LLMCanary_CL` is
  assumed.
- Tests: 153 passed; yamllint clean; `dac validate` with ATT&CK and
  ATLAS data passes; `python -m harness run --engine kusto` passes for
  all ten rules.

## 2026-10-28 - CI on main: deploy red by design, coverage never ran

- Owner asked whether PRs #3-#5 had merge conflicts. None did: each PR
  branch started from the previous merge and main had no other commits;
  `git show --remerge-diff` is empty for every merge commit, and main's
  tree equals PR #5's head tree.
- Found while checking: the push-to-main workflow has been red since
  PR #3. Cause: `demo` has no log-source confirmations, so the gate
  blocks every included rule and `dac deploy` exits 2 (documented
  behaviour in docs/components/ci.md). Validate, engine-kusto and
  customers are green on main. The coverage job `needs` deploy, so it
  was skipped on every one of those runs: the coverage CI job had not
  run on main since PR #3.
- Fixed: coverage now runs unless the run is cancelled or the customers
  job failed. Run locally for `demo`: exits 0, 0 of 6 applicable rules
  active, each blocked rule with its reason. Not yet verified on GitHub.
- Decision for the owner: whether a blocked rule should keep the deploy
  job red (current, a visible signal) or be reported without failing
  the job. Deploy will stay red until the owning teams confirm sources.
