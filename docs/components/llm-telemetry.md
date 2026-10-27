# LLM telemetry and the LLM log-source inventory

What: the logging standard every LLM detection rule in this repo builds
on. One normalised table (`LLMAppLog_CL`), one inventory of LLM log
sources (`llm_log_inventory.yaml`), one per-customer list of LLM apps
(`customers/<id>/llm_apps.yaml`), and a report that joins them
(`python -m dac llm-inventory`). Decision record: ADR 008. Procedure:
the `llm-log-inventory` skill.

## Why it exists
Endpoint and identity rules read logs that every tenant has in the same
shape (Security events, Entra audit logs). LLM apps have no such log:
- No public, recorded LLM-application log exists to test against.
- Each gateway and cloud logs a different subset, mostly off by default,
  and none logs the agent's tool calls as rows.
- The OpenTelemetry GenAI semantic conventions are the nearest standard
  (status Development) and make all content opt-in.
So the practice is: decide one normalised shape, record for every
source how it maps onto that shape and what it cannot provide, and make
each rule declare what it needs, so a gap is visible before a rule is
deployed blind.

## The normalised table
`schemas/reference/sentinel/LLMAppLog_CL.yaml`; per-column source
attributes in `llm_log_inventory.yaml` under `normalised_schema`. One
row per span:

| Operation (`OperationName`) | `InputText` | `OutputText` |
|---|---|---|
| `chat` (model call) | latest user message | the model's answer |
| `execute_tool` (tool call) | arguments the model chose | the tool's result |
| `retrieval` (RAG lookup) | the query | documents returned |
| `invoke_agent` | - | - |

Plus who and where (`AppName`, `AgentName`, `ConversationId`, `UserId`,
`ClientIp`, `TraceId`/`SpanId`), what (`ProviderName`, `RequestModel`,
`ToolName`, `ToolCallId`), cost (`InputTokens`, `OutputTokens`), outcome
(`FinishReason`, `ErrorType`, `GuardrailAction`, `GuardrailCategories`)
and `LogSource` (which inventory source produced the row).

`LLMCanary_CL` holds the canary registry (C2): `AppName`, `CanaryValue`,
`PlantedIn`, re-sent at least hourly.

Why this shape: rules filter on the operation first, then read one text
column, so the same pattern logic covers direct prompts and indirect
content (C1). Keeping one row per span keeps tool calls countable (C3).
Text columns keep what the model saw and did; the alternative of
storing full message arrays (`gen_ai.input.messages`) per row repeats
the whole conversation on every call.

## The inventory
`llm_log_inventory.yaml`, one entry per source:

| Source | Kind | Status | Gives | Main gaps |
|---|---|---|---|---|
| `otel-genai` | logs | recommended | every span type, conversation id, tokens; content opt-in | no user id or guardrail attribute; Development status |
| `mcp-server` | logs | supported | tool calls at the MCP server | no prompts, outputs or tokens; session is not a conversation |
| `azure-apim-ai-gateway` | logs | partial | prompts and answers (opt-in), tokens | no conversation id, no caller column, tool calls only inside bodies, 32 KB chunks |
| `aws-bedrock-invocation` | logs | partial | request and response bodies (off by default), tokens, AWS principal | no conversation id, end user not the principal, bodies over 100 KB in S3 |
| `azure-openai-diagnostics` | logs | not-verified | category names only | fields undocumented on the page read |
| `gcp-vertex-ai` | logs | not-verified | nothing claimed | page not readable from this environment |
| `defender-for-ai-alerts` | alerts | alerts-only | jailbreak, ASCII smuggling, credential theft, wallet, anomalous tool alerts | alerts, not logs; Azure only |
| `llm-canary-registry` | config | recommended | active canaries for C2 | a job to build; must re-send hourly |

Each entry also lists `maps_to` (vendor field to normalised column),
`integration` for Sentinel, Splunk and SecOps, and `verified` /
`not_verified` with the vendor page and fetch date.

### Integration, in short
- **Sentinel**: OpenTelemetry Collector (or a small forwarder) posts
  JSON arrays to the Azure Monitor Logs Ingestion API; a data collection
  rule's transformation maps attributes to `LLMAppLog_CL` columns. The
  API writes only to existing tables, custom table names end in `_CL`,
  and it authenticates with an Entra app holding Monitoring Metrics
  Publisher on the DCR (Microsoft page updated 2026-10-15). Gateway
  sources that land in their own tables need a copy job (not built).
- **Splunk**: OpenTelemetry Collector to the HTTP Event Collector,
  `POST /services/collector/event` with `Authorization: Splunk <token>`,
  one event per span with the normalised column names (Splunk page
  updated 2026-02-18). No LLM rule has an SPL version yet.
- **SecOps**: not verified; no ingestion documentation was fetched.

## Per-customer apps and the feed report
`customers/<id>/llm_apps.yaml` lists the customer's LLM apps: owner
team, sources, whether content capture is on, and columns the app adds
itself (e.g. `UserId`). `python -m dac llm-inventory --customer <id>`
writes `reports/llm/<id>.md`: per app, per LLM rule, "can feed" or the
missing columns and tables, plus the known gaps of the app's sources.
Exit code 2 if any app cannot feed any LLM rule, so it can gate a CI job
if a customer wants that (not wired into CI today; the log-source gate
still decides deployment).

How a rule is judged fed: every column in its `llm_telemetry.populated`
is mapped by one of the app's sources (`maps_to`) or added by the app;
content columns also need `content_capture: true`; every other table
in its `required_fields` (the canary table) must come from one of the
app's sources.

## Checks
`python -m dac validate`:
- inventory structure: required keys per source, known `kind` and
  `status`, `log_source` in `log_sources.yaml`, https `source_url`, all
  record keys present, `maps_to` names only normalised columns,
  `integration` covers sentinel, splunk and secops;
- `llm_apps.yaml`: known sources, owner team in `teams.yaml`, boolean
  `content_capture`, known columns in `adds_columns`;
- rules reading `LLMAppLog_CL` have `llm_telemetry.populated`, naming
  only columns in their `required_fields`.

## Testing
The harness loads `LLMAppLog_CL` and `LLMCanary_CL` rows as they are
(`harness/mapping.py`, `NATIVE_TABLES`) and converts three open datasets
into them (`harness/llm_datasets.py`; docs/components/engine-tests.md):
JailbreakHub prompts (real prompts, no answers), AgentDojo runs (a real
model calling simulated tools, synthetic timestamps), BIPIA (attack
texts appended to emails by the converter). Results per dataset label
are in each rule's `tests/results/kusto.json` under `scores`.

## Advantages
- A new LLM rule is written once, against one table, and its data needs
  are checkable per customer before deployment.
- Gaps are explicit: "this app cannot feed C3 because the gateway has
  no conversation id" is a report line, not a silent rule.
- Following OpenTelemetry keeps the app side vendor-neutral; an app
  instrumented once can feed any SIEM.

## Limits
- The table, the normalisers and the registry are this project's
  design; none has run against a real app or workspace.
- The inventory says what vendors document, as read on the fetch date;
  vendor logs change, and Development-status conventions will.
- The feed report trusts the inventory and the app owner's flags; it
  does not look at data. The schema check and the gate's probe remain
  the check that the table exists.
- Content capture puts prompts and tool data in the SIEM: retention,
  access control and redaction are the customer's decisions and are not
  handled here.
