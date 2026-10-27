# 002. One adapter interface, dry-run by default, credentials only from env

## Status
Accepted (2026-10-27)

## Context
No Sentinel, Splunk or SecOps environment exists for this project, but
the pipeline should be complete enough that adding API credentials is
the only step left before real deploys.

## Decision
`dac/adapters/base.py` defines `SiemAdapter` with four methods:
`check_query` (offline structural checks), `build_request` (the exact
HTTP request, no network), `auth_headers` and `deploy`. Each SIEM is one
subclass. HTTP goes through a small `Transport` object so tests can
swap in a fake one.

- **Dry-run is the default.** `python -m dac deploy` writes each request
  to `build/<siem>/<rule-id>.json` with auth headers redacted. `--mode
  live` calls the API; `--mode auto` (used by CI) goes live only when
  every credential env var for that SIEM is set.
- **Credentials only from environment variables**, set from GitHub
  Actions secrets. Nothing in the repo holds a key. SecOps takes a
  short-lived access token minted by a CI step (workload identity), so
  no long-lived Google key exists anywhere.
- **Deploys are idempotent.** Sentinel: PUT keyed on the rule UUID.
  Splunk: saved search named `dac_<uuid>`, create then update on 409.
  SecOps: rule named `dac_<uuid_with_underscores>`, found by listing,
  then PATCH or create.
- **Experimental rules deploy disabled**, so they can be reviewed in the
  SIEM without raising alerts.

## Alternatives considered
- **Vendor SDKs or Terraform providers.** More complete, but three
  heavy dependency trees for three calls, and they hide the requests,
  which is the thing worth showing in a portfolio repo.
- **Separate scripts per SIEM.** Simpler on day one; duplicates the
  gate, dry-run and credential handling three times.
- **Calling a mock server over HTTP in tests.** More realistic than a
  fake transport, but the fake is enough to check what is sent, and
  neither proves a real API would accept it.

## Consequences
- Tests prove the requests match our reading of each vendor's REST
  reference. They do not prove a live API accepts them. The response
  fixtures in `tests/fixtures/api/` were written from docs, not
  recorded; replace them with recorded responses on the first live call.
- `check_query` is not a parser for KQL, SPL or YARA-L. It catches
  truncated queries and queries that do not touch their declared
  sources, nothing more. See docs/components/validation.md.
