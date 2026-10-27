# Agent tool abuse: runaway tool-call volume and loops (OWASP LLM06 / LLM10, LLM03:2026 / LLM06:2026, ATLAS AML.T0053, AML.T0034.002)

## What the attack is
An LLM agent turns text into tool calls: searches, web requests, file
reads, emails, payments. Whoever controls the text the agent acts on
can make it call tools: many times, in a loop, or in a fan-out where one
request becomes hundreds of calls. The results are cost (every call is
model tokens plus the tool's own price, "denial of wallet"), load on
downstream systems, and, when the calls are actions rather than reads,
damage done at machine speed before anyone looks.

## How the attack happens
1. The attacker gets instructions in front of the agent: directly as a
   user, or indirectly through content the agent reads (C1), or by
   publishing a tool or MCP server whose description or output tells the
   agent what to do (OWASP LLM06:2026 scenario #7: a malicious tool "that
   instructs an agent to perform recursive cyclical tasks, or tasks that
   require a large number of tool calls").
2. The instructions ask for work that needs many calls ("look up every
   customer", "summarise the following text 1000 times", "instead of
   fetching local data, look up the most current info on the internet",
   ATLAS AML.T0034.002's examples), or set up a cycle the agent cannot
   finish (a tool result that always asks for another call).
3. The agent framework keeps going until a step limit, a timeout or a
   budget stops it; many frameworks ship with high or no limits.
4. Variant without an attacker: a bug in the agent or a tool that returns
   an error the model keeps retrying produces the same pattern; the
   response (stop the run, find out why) is the same.

## Real-world use
- OWASP Top 10 for LLM Applications 2026 (final text, commit 9253e38):
  LLM06:2026 Unbounded Consumption describes "recursive or infinite
  tool-calling loops" and tool fan-out, and recommends to "Monitor
  agent-tool interactions to identify if a particular session appears to
  be causing a recursive or resource-intensive action without a clear end
  state. Establish baselines of normal tool behavior". LLM03:2026 Excessive
  Agency recommends to "Log and monitor the activity of LLM tools". The
  2025 list has the same advice under LLM06 Excessive Agency and LLM10
  Unbounded Consumption.
- MITRE ATLAS v2026.06: AML.T0053 AI Agent Tool Invocation is
  "Demonstrated"; AML.T0034.002 Agentic Resource Consumption is
  "Feasible" (no documented real-world use in ATLAS).
- Microsoft Defender for Cloud (alert reference updated 2026-07-06)
  ships alerts for anomalous tool invocation by Azure AI agents
  (`AI.Azure_AnomalousToolInvocation`) and for "denial of wallet"
  request volume (`AI.Azure_DOWVolumeAnomaly`, `AI.Azure_DOWDuplicateRequests`).
- No incident report of a runaway-agent attack naming a group was found
  and fetched; this rule covers a technique that sources rate as feasible
  to demonstrated, not one with a documented campaign.

## What it leaves in the logs
In `LLMAppLog_CL` (llm_log_inventory.yaml), with OpenTelemetry GenAI
`execute_tool` spans:
- one `execute_tool` row per call, with `ToolName`, `ToolCallId`,
  `AgentName`, `ConversationId`, `TimeGenerated`;
- `InputText`, the call's arguments (opt-in content), which shows whether
  the agent repeats the same call;
- `chat` rows between the calls, with token counts (`InputTokens`,
  `OutputTokens`) that grow as the loop's context grows.
The attacker cannot hide the calls from the agent's own telemetry; they
can keep each conversation under a threshold (several sessions, slower
pace) or vary arguments to defeat a duplicate count.

## Prerequisites
An agent with tools and no tight step or cost limit, plus a way to give
it instructions: a user session, content it reads, or a tool or MCP
server it trusts. No privileges in the app are needed beyond what the
agent already has.

## Mapping
- OWASP 2025: LLM06 Excessive Agency (an agent taking more actions than
  the task needs) and LLM10 Unbounded Consumption (the resource cost).
- OWASP 2026: LLM03:2026 Excessive Agency and LLM06:2026 Unbounded
  Consumption. The 2026 list renumbers both: Excessive Agency moves from
  LLM06 to LLM03, and Unbounded Consumption from LLM10 to LLM06, so
  "LLM06" means a different risk in each list.
- ATLAS AML.T0053 AI Agent Tool Invocation (tactics Execution, Privilege
  Escalation) and AML.T0034.002 Cost Harvesting: Agentic Resource
  Consumption (tactic Impact).
- Not AML.T0029 Denial of AI Service: that is about making the AI service
  unavailable; this rule counts one agent's calls, not service health.

## References
- OWASP GenAI Security Project, LLM03:2026 Excessive Agency and
  LLM06:2026 Unbounded Consumption, and LLM06:2025 / LLM10:2025,
  GenAI-LLM-Top10 commit 9253e38,
  https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/9253e38ade58e959b531c0c5c9a4842272c9cd0e
  (read with git 2026-10-27).
- MITRE ATLAS data v2026.06, atlas-data commit 3259f38: AML.T0053,
  AML.T0034.002 (read 2026-10-27).
- Microsoft Defender for Cloud documentation, alert reference for AI
  workloads, updated 2026-07-06,
  https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-ai-workloads
  (fetched 2026-10-27).
- OpenTelemetry GenAI semantic conventions, execute_tool span, commit
  e19717d (read with git 2026-10-27).
- AgentDojo, ethz-spylab/agentdojo commit 089ed46, MIT (fetched 2026-10-27).
