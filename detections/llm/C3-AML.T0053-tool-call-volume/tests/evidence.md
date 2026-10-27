# Evidence: C3-AML.T0053-tool-call-volume

Rule version 1, run on 2026-10-27. Raw output: `results/kusto.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule C3`; see docs/components/engine-tests.md.

## Read this first

No public, recorded log of a production LLM agent exists, and no public
dataset records an agent in a runaway loop or a tool-abuse burst. The log
format is this project's own `LLMAppLog_CL` (ADR 008). All positive
samples are hand-written; the recorded AgentDojo runs serve only as
real, ordinary agent traffic that must not alert. The evidence is weaker
than for the endpoint and identity rules.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. ADX engine, not Log Analytics; no Sentinel workspace was used.
- The query uses `ago()`. `tests/datasets.yaml` sets `rebase_time: true`: for each load (positives, negatives, datasets) the harness shifts every timestamp by the same amount so the newest row is two minutes before the run. Relative spacing is kept. The result file records `"time_rebased": true`.
- Sentinel only; no SPL or YARA-L version.

## Samples

| Positive events | Positive cases | Rows | Negative events | Rows |
|---|---|---|---|---|
| 480 | 3 | 3 | 634 | 0 |

All hand-written. Positives: 60 distinct calls in 40 minutes with no agent history (floor); the same call 25 times in 20 minutes (loop, under the floor); 95 calls in an hour for an agent whose history is ten 30-call conversations (above 3 x p95 = 90).

Negatives (6 cases), each shown to alert when the clause it tests is changed: 45 calls (floor 50 lowered to 40); the same call 19 times (loop threshold 20 lowered to 19); 70 calls over two hours with 30 inside the last hour (window widened to 2 hours); 80 calls for the agent with a 90-call threshold (factor 3 lowered to 1); 60 `chat` rows (operation filter removed); 60 calls split over three conversations (grouping by conversation removed).

## Recorded datasets

| Dataset | What it is | Licence | Rows loaded |
|---|---|---|---|
| agentdojo-claude37-banking-slack | ethz-spylab/agentdojo @ 089ed46, 300 recorded runs of claude-3-7-sonnet-20250219 (banking 169, slack 131), per-file SHA-256 in `harness/manifests/` | MIT | 2,884 (1,143 `execute_tool`) |

| Engine | Rows returned |
|---|---|
| kusto | 0 |

The converter places runs 10 minutes apart, so after rebasing 6 slack runs fall in the last hour and the other 294 form the baseline (slack: 125 conversations, 95th percentile 13 calls; threshold 50). The 6 in-window runs made 6 to 9 calls each. Across all 300 runs, outside the rule: at most 16 tool calls in one run (slack), at most 5 (banking), and at most 10 identical calls in one run (`get_channels` with no arguments, in an injected slack run where the agent kept re-reading the channel list). No run would cross either threshold wherever it fell in time.

## What this does not show

- That the rule fires on a real runaway agent: no such recording exists publicly; the positives are written to the thresholds.
- That the thresholds suit any real agent: they are judgment calls; AgentDojo's tasks are short (median 2 calls).
- Behaviour with real timestamps: AgentDojo runs have none, so the baseline/window split above is an artefact of the converter's 10-minute spacing.
- That the rule runs in a Log Analytics workspace (ADX engine instead).
