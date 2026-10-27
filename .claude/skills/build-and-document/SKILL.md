---
name: build-and-document
description: "Use whenever building or changing pipeline code (dac/, CI, schemas, adapters, the gate) or making a design decision in this repo. Keeps the component docs, ADRs, CLAUDE.md and BUILD_LOG.md in step with the code as it is built, not reconstructed afterwards."
---

# Build and document

The documentation is part of the deliverable. Every component has a
doc that answers, for a reader who did not build it: what it does, how
it works, why this method over the alternatives, its advantages, and
what it does not do.

## Every build session, in order

1. **Read CLAUDE.md first** for scope, conventions and current state.
2. **Say the decision before writing the code.** When there is a real
   choice ("we could do X, we do Y because Z"), state it in the
   response first.
3. **Write tests with the code.** `python -m pytest` before every
   commit. A test name and docstring say exactly what is tested.
4. **Update the component doc** in `docs/components/` for anything
   whose behavior changed. Keep its "What it does not do" section
   honest: list what is not checked, never claim a check "closes" a
   problem.
5. **Write an ADR** (`docs/decisions/NNN-title.md`: Status, Context,
   Decision, Alternatives considered, Consequences) when a real
   decision point was crossed. ADRs are append-only: correct one with a
   dated amendment, not a silent edit.
6. **Update CLAUDE.md** (current state, overwrite stale parts) and
   **append to BUILD_LOG.md** (dated; what was built, what is real vs.
   mocked or unverified, what is next).

## Related skills
- Adding or changing a rule: `new-detection`.
- Anything blocked by or changing the log-source gate: `log-source-gate`.
- Required fields, probes, customer schemas: `schema-check`.
- ATT&CK / ATLAS mapping, rule tier, coverage reports: `coverage-map`.

## Commit conventions
One commit per logical unit. The message says why, not just what:
```
gate: confirm per log source, not per rule

Per-rule confirmations would ask the same team the same question on
every query tweak. See docs/decisions/003-log-source-gate.md.
```

## Do NOT
- Don't describe unbuilt features as built, or unverified API calls as
  working. Every live-API claim stays "not verified" until a live call
  has been made and logged in BUILD_LOG.md.
- Don't add rules, SIEMs or features beyond CLAUDE.md's scope without
  the owner's explicit go-ahead. Park ideas in BUILD_LOG.md.
- Don't commit secrets, real tenant names or customer data.
