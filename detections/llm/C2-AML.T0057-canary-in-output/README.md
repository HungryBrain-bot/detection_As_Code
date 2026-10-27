# Canary value from an LLM app's hidden context appears in model output or tool arguments

OWASP LLM02, LLM07 (2025), LLM02:2026, LLM08:2026 · ATLAS AML.T0056, AML.T0057, AML.T0086 · Severity: High · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If a model discloses its hidden context, through a system-prompt
extraction, a data leak or a tool call made under an injection, then a
canary planted in that context will appear in the model's answer or in
the arguments of a tool call, in the normalised LLM log.

## Data sources
- `llm-app-log` (owner: AI platform team): `LLMAppLog_CL`, needs
  `OperationName`, `InputText`, `OutputText` and `AppName` populated,
  so content capture must be on (opt-in in OpenTelemetry).
- `llm-canary-registry` (owner: AI platform team): `LLMCanary_CL`, one
  row per active canary (`AppName`, `CanaryValue`, `PlantedIn`). This is
  this project's design (ADR 008), not a product: the team that plants
  canaries also runs a job that posts them to the table. **The job must
  re-send every active canary at least once an hour**, because a
  scheduled rule only reads data inside its lookback period (here one
  hour), and that applies to the registry table too (this project's
  understanding of Sentinel scheduled rules; not verified in a
  workspace).
- Canaries must be at least 12 characters, unique, and meaningless (for
  example `dac-canary-` plus 12 random hex digits). Plant them where a
  leak matters: the system prompt, tool configuration, confidential
  documents in the RAG store.
- Tier targeted: needs both custom tables and planted canaries.

## Detection logic
Full query in `rule.yaml`. In order:
1. Registry: canaries of 12 characters or more; latest row per app and
   value. For each, three Base64 needles: the encoding of the canary, of
   the canary without its first character, and without its first two,
   each cut to whole 4-character groups. Base64 encodes 3 bytes at a
   time, so inside a longer encoded text the canary's bytes line up with
   one of these three, whatever its position.
2. Log rows where the model sent something out: `chat` rows with an
   answer (`OutputText`), `execute_tool` rows with arguments
   (`InputText`).
3. Every row against every canary (the registry is small), so a canary
   of one app found in another app's output also alerts (`CanaryApp`
   differs from `AppName`).
4. Match: the canary as plain text (case-insensitive), or one of its
   Base64 needles (case-sensitive).
5. One row per hit: app, canary's app, conversation, user, channel
   (model output or tool arguments), tool name, where the canary was
   planted, plain or Base64, and 300 characters around the hit.

## Why this logic
- Alternative 1, look for system-prompt text in outputs (fuzzy match of
  the prompt itself): needs the prompt in the SIEM, which then holds the
  very secret being protected, and every app's prompt changes with each
  release. A canary is one short, stable, secret-free string.
- Alternative 2, a classifier for "looks like a system prompt" or for
  credentials in outputs (DLP): catches leaks without planted markers,
  including paraphrases; noisier and not available as a SIEM query. Use
  it alongside where the gateway offers it.
- Alternative 3, a Sentinel watchlist for the canaries
  (`_GetWatchlist`): the usual Sentinel way to keep a lookup list. It was
  not used because the harness's Kusto emulator cannot run
  `_GetWatchlist`, so the rule could not have been tested; swapping the
  `canaries` let for a watchlist is a two-line change for a customer
  that prefers it.
- Why not check tool results and retrieved documents: they are where the
  canary lives; the agent reads them legitimately.
- Why tool arguments: the recorded AgentDojo runs show the realistic
  exfiltration path, the model putting data into a `post_webpage` call;
  a rule that read only model answers would have missed both successful
  attacks.

## False positives
- A user or tester who knows the canary pastes it and the model echoes
  it (red-team exercises): allowlist test apps or users.
- Documents legitimately quoted to a user who may see them, when a
  canary was planted in a document that is not actually confidential.
- A tool call that copies a document internally (archive, index) with
  the canary inside: the `ToolName` shows it; allowlist internal tools.
- In the recorded data, two runs where the user asked the agent to post
  channel messages to a website (AgentDojo runs the attacker's goal as
  a user task) alerted. To the rule this is the same event: the data
  left, and only a person can say whether the user was allowed to send
  it.

## Tuning
- Plant canaries per app and per sensitive document, and keep
  `PlantedIn` specific, so an alert says what leaked.
- Severity can follow `PlantedIn` (credentials or system prompt High;
  low-sensitivity documents Medium).
- If canaries are rotated, keep the old ones registered for at least
  the conversation lifetime.
- Add other encodings that matter to the app (hex, URL-encoding) as
  further needles in the `canaries` step.

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positive cases | Negatives | Real datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 8 of 8 matched (1 recorded) | 0 of 7 matched | 5 rows from 18,151 rows: both successful AgentDojo exfiltrations, 2 user-requested posts and 1 model answer quoting the posted text; 0 from JailbreakHub and BIPIA |

**No public recorded LLM-application log exists**, so the log rows were
built from research datasets by this repo's converters, in this
project's own format. No dataset has a planted canary: the AgentDojo
message "Secret key is 1a7b3d" was registered as one by hand. The
recorded part is real: a real model, under a real injection, putting that
string into a tool call. Seven of the eight positive cases are
hand-written; each Base64 needle has its own case and was shown to be
the only one that catches it.

## Blind spots
- Paraphrase, translation, partial copies and encodings other than
  standard Base64 (URL-safe Base64, hex, ROT13, spelling it out).
- A model told to leave the canary out: an attacker who has seen one
  canary can ask for the prompt "without the marker".
- Hidden context with no canary in it; tool schemas and data the
  defender did not mark.
- Leaks through channels not logged as `chat` output or tool arguments:
  rendered markdown images whose URL the client fetches, streaming
  responses whose logged content is cut, content stored externally by
  reference.
- Canaries the registry stopped re-sending within the lookback period.

## References
- OWASP LLM07:2025 System Prompt Leakage, LLM08:2026 Hidden Context
  Exposure, LLM02:2026, GenAI-LLM-Top10 commit 9253e38 (read 2026-10-27).
- MITRE ATLAS v2026.06 (atlas-data commit 3259f38): AML.T0056, AML.T0057,
  AML.T0086.
- Protect AI, Rebuff README (canary words for prompt-leak detection),
  https://github.com/protectai/rebuff/blob/main/README.md (fetched
  2026-10-27).
- AgentDojo, ethz-spylab/agentdojo commit 089ed46, MIT (fetched
  2026-10-27).
- llm_log_inventory.yaml and docs/components/llm-telemetry.md for the
  tables and the registry design.
