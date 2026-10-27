# Abnormal tool-call volume or a tool-call loop in one LLM agent conversation

OWASP LLM06, LLM10 (2025), LLM03:2026, LLM06:2026 · ATLAS AML.T0053, AML.T0034.002 · Severity: Medium · Status: test · Tier: targeted · Targets: sentinel

## Hypothesis
If an agent is driven into tool abuse, by injected instructions, a
malicious tool, a hijacked session or its own bug, one conversation will
make far more tool calls in a short time than that agent's
conversations normally make, or will repeat the same call over and over,
in the normalised LLM log's `execute_tool` rows.

## Data sources
- Log source `llm-app-log` (owner: AI platform team): `LLMAppLog_CL`
  `execute_tool` rows. Needs populated: `OperationName`, `AppName`,
  `AgentName`, `ConversationId`, `ToolName`, and `InputText` (tool
  arguments, opt-in content) for the loop check.
- Sources that can feed it: OpenTelemetry GenAI spans from the agent
  framework, MCP server spans (tool side). Gateway logs (API Management,
  Bedrock) cannot: they have no conversation id and no tool-call rows
  (llm_log_inventory.yaml, gaps). Without `InputText` the volume check
  still works and the loop check never fires.
- `ConversationId` must identify one agent run or chat session
  (`gen_ai.conversation.id`); if the app reuses one id for a user's whole
  history, the counts mean "per user".
- Tier targeted: custom table, and thresholds need a week of the
  customer's own traffic.

## Detection logic
Full query in `rule.yaml`. Runs hourly over 7 days:
1. `execute_tool` rows only.
2. Baseline: tool calls per conversation for every conversation in the
   7 days before the last hour, then per app and agent the 95th
   percentile and the number of conversations.
3. Last hour: per conversation, the number of calls, distinct tools, the
   tool list, users, first and last call.
4. Loop: per conversation in the last hour, the most repeated identical
   call (same `ToolName` and same arguments) and its count.
5. Threshold = the larger of 50 calls and 3 times the agent's baseline
   95th percentile (50 when the agent has no history).
6. Alert when calls in the last hour exceed the threshold ("volume"), or
   one identical call was made 20 or more times ("loop"), or both.

## Why this logic
- Alternative 1, a fixed limit only (e.g. 50 calls per conversation):
  simple, but agents differ by orders of magnitude (a research agent
  doing 100 searches is normal, a support bot doing 20 is not). The
  per-agent baseline adapts; the floor of 50 stops alerts on agents
  whose normal is tiny (AgentDojo's banking agent: 95th percentile 3
  calls, so 3 x p95 alone would alert at 10).
- Alternative 2, a statistical anomaly function (`series_decompose_anomalies`)
  over calls per hour per agent: catches an agent-wide surge across many
  conversations, which this rule misses (see Blind spots), but not one
  bad conversation inside normal total volume. A second rule if
  needed.
- Alternative 3, token or cost totals instead of call counts: closer to
  "denial of wallet" (LLM10 / LLM06:2026), but token columns are often
  missing (API Management drops them on broken streams) and tool calls
  cost money outside the model too. Counting calls needs only the span.
- Loop on identical arguments: OWASP LLM06:2026 recommends "state
  hashing to detect recursive loops"; same tool plus same arguments is
  that hash for a single step. In the recorded AgentDojo runs an
  injection-confused agent called `get_channels` with no arguments 10
  times in one run; 20 leaves a margin over that.
- The thresholds (50, 3x, 20) are judgment calls, not derived from data:
  no production agent baseline was available.

## False positives
- Batch agents that legitimately loop over many items (one call per
  document, per customer, per page).
- Polling tools (status checks, waiting for a job), which repeat the
  same call by design.
- A new agent version that makes more calls than the old one: the
  baseline catches up after a few days.
- Shared or reused conversation ids that merge several runs.

## Tuning
- Raise the floor or exclude `ToolName` values that poll; set a
  per-agent floor for batch agents.
- Lower the factor to 2 for agents with very regular behaviour.
- Add severity when the tools in the burst can act (send, pay, delete,
  write) rather than read: `Tools` lists them.
- Combine with C1 on the same `ConversationId`: an indirect injection
  followed by a burst is the attack chain this rule exists for.

## Test evidence
Run on 2026-10-27; details in [tests/evidence.md](tests/evidence.md).

| Engine | Positive cases | Negatives | Real datasets |
|---|---|---|---|
| Kusto (ADX emulator) | 3 of 3 matched (hand-written) | 0 of 6 cases matched (hand-written) | 0 alerts on 300 recorded AgentDojo runs (1,143 tool calls; max 16 calls and 10 identical repeats per run) |

**No public recorded log of a production agent exists**, and no public
dataset records a runaway agent, so every positive is hand-written. The
recorded AgentDojo runs only show that ordinary and injected runs (231
with the injection reaching the agent) stay far below the thresholds.
Their timestamps are synthetic (the runs have none), and the harness
shifts all timestamps so the newest row falls two minutes before the
run, because the query uses `ago()`. The evidence is weaker than for the
endpoint and identity rules.

## Blind spots
- Abuse spread over many conversations or users, each under the
  threshold (an agent-wide surge; Alternative 2).
- Slow abuse: fewer than 50 calls an hour, kept up for days.
- Loops that vary the arguments slightly (a counter, a timestamp), which
  the identical-call check misses.
- Harmful calls in small numbers: one `send_money` call made under an
  injection is the worst case and is far below any volume threshold
  (C1 and C2 look for that chain).
- Tool calls not logged as `execute_tool` spans (tools called by the app
  outside the agent framework, MCP servers without telemetry).
- The first hour of a new agent with no history uses only the floor.

## References
- OWASP LLM03:2026 Excessive Agency and LLM06:2026 Unbounded Consumption
  (GenAI-LLM-Top10 commit 9253e38, read 2026-10-27): monitoring tool
  interactions, baselines of normal tool behaviour, state hashing.
- MITRE ATLAS v2026.06 (atlas-data commit 3259f38): AML.T0053,
  AML.T0034.002.
- Microsoft Defender for Cloud, alert reference for AI workloads,
  updated 2026-07-06 (anomalous tool invocation, denial-of-wallet alerts),
  https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-ai-workloads
  (fetched 2026-10-27).
- AgentDojo, ethz-spylab/agentdojo commit 089ed46, MIT (fetched
  2026-10-27).
