---
name: llm-log-inventory
description: "Use for any LLM-track work: writing or changing an LLM detection rule (prompt injection, data leakage, agent tool abuse or any future one), adding or changing an LLM log source (gateway, cloud AI service, agent framework, MCP server), onboarding a customer's LLM app, or answering which LLM logs a customer needs and how to integrate them."
---

# LLM log-source inventory

How it works and why: docs/components/llm-telemetry.md and
docs/decisions/008-llm-telemetry.md. This skill is the procedure. It
applies to every LLM rule, not only C1-C3.

## The standard, in four lines
- Every LLM rule reads `LLMAppLog_CL` (and, if it needs a lookup, a
  table defined the same way, like `LLMCanary_CL`). Never a vendor table.
- Every LLM log source is an entry in `llm_log_inventory.yaml`.
- Every LLM rule declares `llm_telemetry.populated`.
- Every customer LLM app is an entry in `customers/<id>/llm_apps.yaml`.

## A. Writing a new LLM rule (with the new-detection skill)
1. Read `normalised_schema` and `operations` in `llm_log_inventory.yaml`.
   Filter on `OperationName` first; pick the text column by operation
   (`InputText` is the prompt / tool arguments / retrieval query,
   `OutputText` the answer / tool result / documents).
2. If the rule needs a column that does not exist: stop. Adding a
   column is a change to the standard: update `LLMAppLog_CL.yaml`,
   `normalised_schema`, every source's `maps_to` that can fill it, and
   ADR 008 with a dated amendment. Do not add it in one rule.
3. In `rule.yaml`:
   - `log_sources: [llm-app-log]` (+ `llm-canary-registry` or another
     LLM source id if it reads that table).
   - `mapping`: `owasp_llm_2025`, `owasp_llm_2026` and `atlas`. The 2026
     list renumbers (Excessive Agency LLM06 -> LLM03:2026, Unbounded
     Consumption LLM10 -> LLM06:2026, System Prompt Leakage LLM07 ->
     Hidden Context Exposure LLM08:2026, Supply Chain LLM03 -> LLM04:2026);
     look each ID up in the official repo
     (GenAI-Security-Project/GenAI-LLM-Top10, `2025/` and
     `2026/final/`), never from memory. ATLAS IDs from atlas-data
     `dist/v6/` (the old `dist/ATLAS.yaml` is deprecated).
   - `llm_telemetry.populated`: the columns the query matches or groups
     on. Context columns that are only projected do not belong here.
   - `required_fields.LLMAppLog_CL`: every column the query reads.
4. Data: no public recorded LLM-app log exists. Use the converted
   research datasets in `harness/datasets.yaml` (jailbreakhub-prompts,
   agentdojo-claude37-banking-slack, bipia-email), add others only with a
   licence that allows reuse (Tensor Trust's data repo has no licence
   file: not used), and write a converter in `harness/llm_datasets.py`
   that labels each row in `ConversationId` (`<dataset>:<label>:...`).
   In `tests/datasets.yaml` use `score_by` to report per-label rates,
   `rebase_time` if the query uses `ago()`, `extra_events` for lookup
   rows, `max_matched_rows` for large outputs.
5. Evidence must say, in its first section: no public recorded LLM-app
   log exists; the format is this project's normalised table; which
   rows are converted research data and which hand-written; and that
   the evidence is weaker than for endpoint and identity rules. Report
   recall and alert rates per label; say which numbers are in-sample
   (patterns written after reading that dataset) and keep the first-run
   numbers if you tuned.
6. Rule doc, Data sources: name the needed populated columns, whether
   content capture is required, and which inventory sources can and
   cannot feed it.

## B. Adding or changing an LLM log source
1. Fetch the vendor's own documentation page (or read the spec's repo
   at a pinned commit). If it cannot be fetched, the entry says
   `status: not-verified` and claims nothing.
2. Add an entry under `sources` with every key: `name`, `kind`
   (logs / alerts / config), `status`, `log_source` (an id in
   `log_sources.yaml`, usually `llm-app-log`), `source_url`,
   `fetched_on`, `records` (all seven keys; values like "yes", "no",
   "opt-in", "not documented on the page read"), `maps_to` (normalised
   column -> vendor field, only fields the page names), `gaps`,
   `integration` (sentinel, splunk, secops; "not verified" is a valid
   value), `verified`, `not_verified`.
3. Say what is off by default and what needs a normaliser or copy job.
   A design is not a build: write "not built, not verified".
4. Run `python -m dac validate` and `python -m dac llm-inventory
   --customer demo`. Update the table in docs/components/llm-telemetry.md.

## C. Onboarding a customer's LLM app
1. Ask the app owner (not the SIEM team): which sources the app's
   telemetry comes from, whether content capture is on, and whether the
   app adds a user id. Record the answer in
   `customers/<id>/llm_apps.yaml` with the owner team key from
   `teams.yaml`. Only what the owner stated; never assume content
   capture is on.
2. `python -m dac llm-inventory --customer <id>`: read the "Missing"
   column. Each gap is either a request to the app owner (switch on
   content capture, add `gen_ai.conversation.id`, add the user id) or a
   reason not to include that rule for the customer.
3. Then the normal path: include the targeted LLM rules in
   `customer.yaml`, and the log-source gate asks the AI platform team to
   confirm `llm-app-log` (log-source-gate skill).

## Do NOT
- Don't write an LLM rule against a vendor table, or add a column to
  `LLMAppLog_CL` for one rule.
- Don't present converted research data as recorded app logs, or
  hand-written samples as attack data.
- Don't claim a vendor log has a field because a similar product does;
  only what the fetched page says.
- Don't put real prompts, canaries, keys or customer data in the repo.
- Don't record content capture or an integration as working until the
  app owner or a live run confirms it.
