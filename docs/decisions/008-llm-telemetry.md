# 008. One normalised LLM log table and an inventory of LLM log sources

## Status
Accepted (2026-10-27)

## Context
The LLM rules (C1-C3, and any LLM rule after them) need prompts, model
output and tool calls in the SIEM. Unlike Windows events or Entra logs,
there is no common LLM log:
- No public, recorded LLM-application log dataset exists in any format.
- Vendors each log differently and mostly not by default: Azure API
  Management's AI gateway (`ApiManagementGatewayLlmLog`, message logging
  switched on per API), Amazon Bedrock invocation logging (off by
  default, bodies over 100 KB moved to S3), Azure OpenAI diagnostics
  (categories documented, fields not), Vertex AI (page not readable from
  here).
- The closest thing to a standard is the OpenTelemetry GenAI semantic
  conventions, which define spans for model calls, tool calls,
  retrieval, agents and MCP. They are at status Development, and make
  every content attribute (prompts, outputs, tool arguments and results)
  opt-in: "OpenTelemetry instrumentations SHOULD NOT capture them by
  default".
- They define no end-user identity attribute and no guardrail verdict.
The owner asked for an LLM detection practice, not only three rules: a
list of the log sources to use, the telemetry each gives, how each is
integrated, kept as a log inventory with its own skill, for every
future LLM rule.

## Decision
1. Every LLM rule reads one custom table, `LLMAppLog_CL`, one row per
   OpenTelemetry GenAI span. Columns follow the GenAI attributes
   (`OperationName` = `gen_ai.operation.name`, `ConversationId` =
   `gen_ai.conversation.id`, ...), plus two text columns whose meaning
   depends on the operation (`InputText`: prompt / tool arguments /
   retrieval query; `OutputText`: answer / tool result / documents), plus
   columns the conventions lack (`UserId`, `GuardrailAction`,
   `GuardrailCategories`, `LogSource`). Defined in
   `schemas/reference/sentinel/LLMAppLog_CL.yaml`.
2. `llm_log_inventory.yaml` lists every LLM log source with what it
   records, which normalised column each field fills, its gaps, its
   integration per SIEM, and what was verified against the vendor page.
   `dac validate` checks its structure.
3. A rule that reads `LLMAppLog_CL` declares `llm_telemetry.populated`:
   the columns that must hold values. `dac validate` requires it;
   `python -m dac llm-inventory --customer <id>` checks it against each
   of the customer's apps (`customers/<id>/llm_apps.yaml`) and reports
   which rules each app can feed and what is missing.
4. Canaries for C2 live in a second custom table, `LLMCanary_CL`, fed by
   a registry job (log source `llm-canary-registry`), not a Sentinel
   watchlist, so the rule can run in the test engine.
5. The harness converts open research datasets (JailbreakHub, AgentDojo,
   BIPIA) into `LLMAppLog_CL` rows (`harness/llm_datasets.py`) so the
   rules run on real text. Evidence says plainly that the logs around
   the text are built by this repo.
6. The `llm-log-inventory` skill is the procedure for adding a source,
   onboarding a customer app, and writing a new LLM rule on this table.

## Alternatives considered
- **Write rules against each vendor's table** (one C1 per gateway).
  Every rule times every source, each with different gaps; and the
  agent-side telemetry (tool calls, conversations) is not in gateway
  logs at all.
- **ASIM-style parser functions** (a KQL function that unions vendor
  tables into one shape at query time, as Sentinel's ASIM does). No copy
  job, and the native tables stay as they are. Rejected for now because
  the schema check and the gate probe real tables, the harness cannot
  test functions defined in a workspace, and only one source (OTel) has
  the agent-side fields. Revisit if two gateway sources are onboarded
  for the same customer.
- **Application Insights tables** (`AppDependencies`, `AppTraces`) where
  the Azure Monitor OpenTelemetry exporter sends spans: no normaliser,
  but GenAI attributes land in a generic property bag whose layout was
  not verified here, and the tables are shared with all other app
  telemetry.
- **Wait for a vendor standard.** None is announced; the OpenTelemetry
  conventions are the nearest, so the table follows them and the
  inventory records the version used.

## Consequences
- One place to change when the conventions change: the column mapping
  in the inventory and the normaliser, not every rule.
- The normalisers for production sources (OTel collector to the Logs
  Ingestion API, the API Management copy job, a Bedrock forwarder) are
  designs in the inventory, not built. Only the dataset converters exist.
- Content capture is a privacy decision: the table holds prompts and
  tool data. Each customer app's owner decides it; the inventory report
  shows which rules are blind without it.
- Not verified: creating `LLMAppLog_CL` in a Log Analytics workspace,
  any DCR transformation, the registry job, and the claim that a
  scheduled rule's lookback also limits the canary table.
