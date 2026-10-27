---
name: coverage-map
description: "Use when mapping a new or changed rule to MITRE ATT&CK or MITRE ATLAS, deciding a rule's tier (baseline or targeted), or producing per-customer coverage for management or a CISO."
---

# Coverage map

How coverage is computed is in docs/components/coverage.md. This skill
covers mapping a rule correctly, and producing and presenting coverage
honestly.

## 1. Mapping a rule (while writing it, with new-detection)
- **Endpoint and identity rules** map to ATT&CK in `mapping.attack`:
  the most specific technique or sub-technique the query actually
  detects, and only tactics that technique belongs to. CI checks both
  against the current STIX bundle.
- **LLM application rules** map to `mapping.owasp_llm_2025`,
  `mapping.owasp_llm_2026` and `mapping.atlas`. The 2026 list renumbers
  risks (see the `llm-log-inventory` skill); the summary prints them as
  `LLM06:2025` / `LLM03:2026` so the two are not confused. ATT&CK has no
  LLM techniques; do not force one.
  Fetch ATLAS IDs from the ATLAS data (github.com/mitre-atlas), never
  from memory.
- Map to what the rule detects, not what the attack eventually does.
  A rule for an encoded PowerShell command line is T1059.001, not
  "Execution" in general and not the payload's later techniques.
- If two techniques are plausible, write why you chose one in the
  attack doc's "Mapping" section. Disputed mappings are an Opus-tier
  call (CLAUDE.md, Model usage).

## 2. Choosing the tier
- `baseline`: native tables that nearly every customer of that SIEM has
  once the standard connector is on, and high value (for example the
  Entra ID rules B1-B3). Goes to every customer unless excluded.
- `targeted`: depends on configuration that varies by customer (Sysmon,
  command-line auditing, a custom LLM gateway log). Customers opt in
  via `include`.
- Either way the gate still applies per customer.

## 3. Producing coverage
```bash
python -m dac coverage --customer <id> --attack-bundle data/enterprise-attack.json
```
Writes `reports/coverage/<id>/attack-layer.json`, `atlas-layer.json`
(if any LLM rule applies) and `summary.md`. In CI this runs on every
push to `main`. Open the layers in the ATT&CK Navigator ("Open existing
layer" -> upload).

## 4. Presenting it
- Lead with the summary's first line ("N of M applicable rules are
  active") and the blocked list: blocked rules show which onboarding
  gaps cost which detections, which is often the actionable part.
- Keep the "How to read this" caveats with the numbers. Never present a
  green cell as "covered" without them: one rule detects one or two
  ways of doing a technique.
- Never count blocked rules, rules the customer does not get, or
  planned rules as coverage.

## Do NOT
- Don't add techniques to a rule's mapping to make the map look fuller.
- Don't edit the generated layer files by hand; fix the rule or the
  gate input and regenerate.
- Don't claim the ATLAS layer loads in the ATLAS Navigator until
  someone has tried it (ADR 006).
