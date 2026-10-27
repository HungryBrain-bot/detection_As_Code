# 004. Per-customer folders and a baseline rule tier

## Status
Accepted (2026-10-27)

## Context
The pipeline is meant for an MSSP-style setup: one rule library, many
customers, each with their own SIEM(s), log sources, owning teams and
credentials. Until now confirmations and teams were repo-wide, which
only works for one tenant. The owner also asked that the most common,
high-value rules on native tables reach every customer by default, so
a new customer gets the important detections without waiting for a
per-rule onboarding decision.

## Decision
- **One folder per customer**, `customers/<id>/`: `customer.yaml`
  (name, SIEMs run, `include`, `exclude`), `teams.yaml`,
  `confirmations/<siem>/`, `schemas/<siem>/`. Rules stay shared in
  `detections/`; nothing about a rule is copied per customer.
- **Rule tiers.** `tier: baseline` rules apply to every customer unless
  listed in that customer's `exclude`. `tier: targeted` (the default)
  rules apply only to customers that list them in `include`.
- **Baseline does not bypass the gate.** A baseline rule is deployed to
  a customer only when its log sources pass that customer's gate. What
  makes baseline fast is the schema probe (ADR 005): where read-only
  credentials exist, a passing probe confirms the source with no human
  step.
- **Credentials per customer** through one GitHub Environment per
  customer, named after its folder, with secrets under the plain names
  the adapters already read. A customer's jobs cannot read another
  customer's secrets.
- One fictional customer, `demo`, ships in the repo.

## Alternatives considered
- **Single tenant, customer as a report label.** Simplest, but a second
  customer would mean restructuring confirmations, teams and secrets.
  Moving now, with zero confirmations, cost almost nothing.
- **A branch or repo per customer.** Strong isolation, but rule fixes
  have to be merged everywhere, and coverage across customers is hard
  to compare.
- **Prefixed secrets in one environment** (`DEMO_AZURE_CLIENT_SECRET`).
  Works without Environments, but every job can read every customer's
  secrets.
- **Baseline as "deploy everywhere without checking".** Fastest, and
  exactly the silent failure the gate exists to prevent: a rule
  deployed against a table the customer does not collect never fires.

## Consequences
- Which rules are baseline is a judgment per rule. Of the agreed 10,
  B1-B3 (Entra ID tables that every Entra tenant has once the connector
  is on) are the natural candidates; endpoint rules depend on Sysmon or
  command-line auditing being configured, so they fit `targeted` better.
  Decided when each rule is built.
- Common high-value rules outside the agreed 10 (for example brute
  force or AD changes) are not added by this decision; they are parked
  in BUILD_LOG.md for the owner.
- GitHub creates an Environment on first use by a workflow; protection
  rules (required reviewers) on a customer's Environment would also
  gate that customer's deploys.
