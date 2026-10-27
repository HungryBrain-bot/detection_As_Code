# Prompt-injection phrasing in a user prompt or in tool and retrieval results

OWASP LLM01 (2025), LLM01:2026 · ATLAS AML.T0051.000, AML.T0051.001, AML.T0054, AML.T0056, AML.T0068 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If an attacker tries to take over an LLM app with a known injection
technique, either by typing it (direct) or by planting it in an email,
page, ticket or tool output the agent reads (indirect), the text will
contain recognisable injection phrasing, and the app's normalised log
will show it in the user's prompt or in a tool or retrieval result.

## Data sources
- Log source `llm-app-log` (owner: AI platform team): the normalised
  table `LLMAppLog_CL`, fed from the sources in `llm_log_inventory.yaml`
  (OpenTelemetry GenAI spans recommended). See the `llm-log-inventory`
  skill and docs/components/llm-telemetry.md.
- Needs populated (`llm_telemetry`): `OperationName`, `InputText`,
  `OutputText`. Both text columns exist only with **content capture
  switched on**, which OpenTelemetry makes opt-in. Without it the rule
  runs and never fires; `python -m dac llm-inventory --customer <id>`
  reports which apps can feed it.
- Direct injection needs `chat` rows; indirect needs `execute_tool` or
  `retrieval` rows with the result text. A gateway-only source (API
  Management, Bedrock invocation logs) sees tool results only inside the
  request body and needs a normaliser that splits them out (inventory,
  gaps).
- Tier targeted: the table is custom and exists only where a customer
  has onboarded an LLM app and decided to log content.

## Detection logic
Full query in `rule.yaml`. In order:
1. Rows for `chat`, `execute_tool` and `retrieval`.
2. Which text to check: for `chat`, the user's prompt (`InputText`,
   surface "direct"); for tools and retrieval, what came back
   (`OutputText`, surface "indirect"). The model's own answer is not
   checked.
3. Seven pattern categories (RE2 regular expressions):
   - override: ignore / disregard / forget / override / bypass, within a
     few words of previous / prior / above / all / your, within a few
     words of instructions / rules / prompt / guidelines / policy.
   - persona: "you are now" + unrestricted / jailbroken, "developer
     mode", "do anything now", "jailbreak", "new instructions:", or
     `DAN` in capitals (case-sensitive, so "Dan" the colleague does not
     match).
   - prompt-extraction: reveal / show / print / repeat / tell me + your /
     the + system prompt / initial instructions / pre-prompt.
   - role-spoofing: chat-template or role markers in text
     (`<|im_start|>system`, `[INST]`, `<<SYS>>`, `<system>`, a line
     starting `system:`).
   - unicode-tags: any character in U+E0000 to U+E007F, invisible when
     rendered (ASCII smuggling).
   - concealment: do not / never + tell / inform / mention + the user.
   - addressed-to-model (indirect only): data that speaks to the AI
     ("to you, Claude", "Note to the assistant", "the AI must ...").
     Data should not address the reader's model; a user prompt
     legitimately does, so this category is not used for `chat`.
4. One row per matching span, with the categories that fired, who (user,
   app, agent, conversation, IP), the tool name and the first 300
   characters of the text.
5. A user's own prompt whose only category is override does not alert
   (see Why this logic). Override in tool and retrieval results always
   alerts.
Runs hourly over the last hour.

## Why this logic
- Alternative 1, a classifier (Azure Prompt Shields, Llama Prompt Guard,
  a fine-tuned model) at the gateway: much better recall on paraphrased
  and indirect attacks, and the right primary control. It blocks inline;
  this rule is the SIEM-side record and a check that works where no
  classifier is deployed. Where a classifier runs, its verdict should be
  logged to `GuardrailAction` / `GuardrailCategories` and alerted on;
  that rule is not in scope here. Defender for Cloud's jailbreak and
  ASCII-smuggling alerts are the managed version for Azure AI services.
- Alternative 2, an LLM judging each logged prompt: too expensive per
  row in a SIEM, and itself injectable.
- Alternative 3, keyword lists (e.g. any text containing "ignore" or
  "jailbreak"): tested in effect by the first run. Loose patterns on
  user prompts alert on 10.6% of JailbreakHub's regular prompts.
- Why user-prompt override alone is excluded: in the only real prompt
  corpus available, "Please ignore all previous instructions. I want you
  to act as ..." is mostly boilerplate from prompt-template sites (1,024
  of 13,735 regular prompts), and a user overriding instructions in
  their own session mostly affects only their own answer. Override
  together with any other category still alerts, and override inside a
  tool or retrieval result always alerts, because there it means someone
  else's text is giving orders. Measured on JailbreakHub: the exclusion
  removes 954 regular-prompt alerts and costs 105 of the 1,405 jailbreak
  prompts. A customer whose chat app has privileged tools should remove
  it.
- Why "from now on you will act as ..." was dropped from persona:
  benign role prompts use it constantly ("From now on, you will play the
  role of a PHP Website Builder Guide"). Measured: keeping it adds 265
  regular-prompt alerts and 86 jailbreak detections.
- Why both surfaces in one rule: the patterns and the response (look at
  the conversation, then at the tool calls that followed) are the same;
  the `Surface` column separates them for triage.

## False positives
- Users discussing prompt injection (security teams, people asking
  what "jailbreak" means) and prompt-engineering content.
- Role-play and character prompts using "DAN" or "developer mode" as a
  name.
- Documents about LLMs retrieved by a RAG app: a design guide quoting
  "ignore previous instructions" as an example is indirect override.
- Chat transcripts or templates stored in documents (`system:` lines,
  `[INST]` markers) and read by an agent.
- Tool results with text addressed to an assistant in good faith
  ("Note to the assistant: this ticket is a duplicate").

## Tuning
- Allowlist by `AppName` for internal red-team or security-training
  apps, and by `ToolName` for tools whose results are known templates.
- For apps with privileged tools, drop the direct override-only
  exclusion (step 5).
- Raise severity when `Surface` is indirect and the same conversation
  then has `execute_tool` rows: the injection may have worked. A
  follow-up join is cheap in Sentinel; not built here.
- The patterns are English only. Add the languages your users use;
  multilingual payloads are a known evasion (OWASP LLM01:2026, example 8).

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positive cases | Negatives | Real datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 7 of 7 matched (2 recorded) | 0 of 7 matched (3 recorded) | JailbreakHub jailbreaks 329 / 1,405 (23%); regular 256 / 13,735 (1.9%); AgentDojo injected 231 / 231 (in-sample); BIPIA injected 0 / 75; benign tool results and emails 0 / 101 |

**There is no public recorded LLM-application log to test against**, so
the evidence is weaker than for the other rules: the text is real
(people's prompts, a real model's agent runs), but the log rows were
built from it by this repo's converters, in this project's own log
format. Hand-written samples are labelled. The AgentDojo result is
in-sample (the addressed-to-model category was written after reading
its attack text); BIPIA is the out-of-sample indirect test, and the rule
catches none of it.

## Blind spots
- Paraphrased or novel injections, and plain task instructions with no
  injection markers (all 75 BIPIA attacks).
- Encoded payloads (Base64, ROT13, emoji, other languages), and payloads
  split across several fields or turns.
- Instructions hidden in images, audio, PDFs or HTML that the app logs
  only as a reference or not at all.
- Variation-selector and zero-width-character smuggling: only the tag
  block (U+E0000 to U+E007F) is checked, because zero-width joiners and
  variation selectors are common in normal emoji text.
- Text longer than the logged content: OpenTelemetry allows storing
  content externally with only a reference on the span, and gateways
  split long messages (API Management: 32 KB chunks).
- Apps with content capture off: nothing to read.
- Whether the injection worked: the rule sees the attempt, not the tool
  calls that followed.

## References
- OWASP LLM01:2026 Prompt Injection, GenAI-LLM-Top10 commit 9253e38
  (read 2026-10-27): attack examples, the Unicode ranges, the
  recommendation to baseline with AgentDojo.
- MITRE ATLAS v2026.06 (atlas-data commit 3259f38): AML.T0051, AML.T0054,
  AML.T0056, AML.T0068 descriptions and tactics.
- OpenTelemetry GenAI semantic conventions, commit e19717d: span types
  and content attributes (docs/components/llm-telemetry.md).
- Datasets: JailbreakHub (verazuo/jailbreak_llms 4f4031b), AgentDojo
  (ethz-spylab/agentdojo 089ed46), BIPIA (microsoft/BIPIA a004b69), all
  MIT, fetched 2026-10-27.
- Microsoft Defender for Cloud, alert reference for AI workloads,
  updated 2026-07-06,
  https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-ai-workloads
  (fetched 2026-10-27).
