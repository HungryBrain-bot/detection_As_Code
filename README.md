# detection_As_Code

Detection rules as code for Microsoft Sentinel (KQL), Splunk (SPL) and
Google SecOps (YARA-L), deployed per customer through a CI/CD pipeline
that validates each rule, probes each customer's SIEM for the tables
and fields the rule reads, holds back rules whose data is not
confirmed (and tells the owning team exactly what is missing), and
reports per-customer coverage as ATT&CK / ATLAS Navigator layers.

**Status (2026-10-27):** the pipeline is built and tested offline, and
seven rules are built: four endpoint rules (A1-A4) and three Entra ID
identity rules (B1-B3, Sentinel only). Their KQL (and the endpoint
rules' SPL) has been run in local engines (Kusto emulator, Splunk
Enterprise container) against recorded open-source attack data; the
endpoint rules' YARA-L has not run anywhere. No live SIEM exists for this project, so every deploy so far
is a dry-run, and every API call (deploy and probe) is written from
vendor documentation, not verified against a live API.

## Rules

| # | Rule | ATT&CK | Tier | KQL / SPL tested on recorded data | YARA-L |
|---|---|---|---|---|---|
| A1 | [Encoded / download-cradle PowerShell](detections/endpoint/A1-T1059.001-encoded-powershell/) | T1059.001 | baseline | yes, 2 rows of 45,370 events, both attack | not run |
| A2 | [Run-key persistence outside installer paths](detections/endpoint/A2-T1547.001-run-key-persistence/) | T1547.001 | targeted | yes, 2 rows, both attack | not run |
| A3 | [SAM / SYSTEM / SECURITY hive dump](detections/endpoint/A3-T1003.002-sam-hive-dump/) | T1003.002 | baseline | yes, 2 rows, both attack | not run |
| A4 | [certutil / bitsadmin / curl download](detections/endpoint/A4-T1105-lolbin-download/) | T1105 | baseline | yes, 1 row, attack | not run |
| B1 | [OAuth consent with mailbox / file / directory-write scopes](detections/identity/B1-T1528-illicit-oauth-consent/) | T1528 | baseline | KQL: yes, 2 rows of 87 Entra records, both attack | n/a (Sentinel only) |
| B2 | [Credential or high-risk permission added to an app](detections/identity/B2-T1098.001-app-credential-or-permission/) | T1098.001 | baseline | KQL: yes, 4 rows, all attack or lab test | n/a |
| B3 | [One sign-in session from two countries](detections/identity/B3-T1550.001-session-token-replay/) | T1550.001, T1550.004 | targeted | KQL ran, but **no recorded sign-in has a SessionId**; positives hand-written | n/a |

Each folder has the attack doc (`attack.md`), the rule doc
(`README.md`), labelled samples and `tests/evidence.md`. "Tested" means
lab data in emulated engines, not a production false-positive rate; see
[engine tests](docs/components/engine-tests.md). Endpoint data is OTRF
Security-Datasets (MIT); Entra data is Splunk attack_data (Apache 2.0)
and OTRF's Golden SAML audit export.

## Architecture

Hand-authored; update when the pipeline changes.

```mermaid
flowchart LR
    RULE["detections/**/rule.yaml<br/>+ README.md + attack.md + tests/"] --> VAL["dac validate<br/>schema · queries · docs ·<br/>ATT&CK bundle"]
    LS["log_sources.yaml"] --> VAL
    CUST["customers/&lt;id&gt;/<br/>SIEMs · teams · confirmations · schemas"] --> GATE
    VAL --> GATE["per-customer log-source gate"]
    LS --> GATE
    GATE <--> SC["schema check<br/>read-only probe or customer schema"]
    GATE -- gap --> NOTIFY["reminder to owning team:<br/>what is missing, send schema if elsewhere"]
    GATE -- passed --> AD["SiemAdapter"]
    GATE --> COV["coverage<br/>Navigator layers + summary"]
    RULE --> HAR["engine harness<br/>Kusto emulator · Splunk<br/>OTRF / Splunk attack_data recorded data"]
    AD --> SEN["Sentinel<br/>PUT alertRules"]
    AD --> SPL["Splunk<br/>saved/searches"]
    AD --> SEC["SecOps<br/>rules (YARA-L)"]
```

## What each part proves

| Part | Proves | Does not prove |
|---|---|---|
| `dac validate` | rule is well-formed, references its declared sources, docs and evidence files exist and are filled, ATT&CK IDs and tactics are real | that a query is valid in its language, or fires on the samples |
| Schema check (probe) | the table / source exists, had events in 24h, and has every field the rule reads, at the time of the run | that field values are usable; probes are unverified against live APIs |
| Log-source gate | each source passed a probe, or (without a probe) the owning team confirmed it within 90 days | on the human path, that events are arriving now |
| Coverage | which techniques have at least one gate-passed rule per customer | that the rule actually catches the technique |
| Adapter tests | requests match the vendor API references as we read them | that a live API accepts them |
| Engine tests (`python -m harness`) | the deployed KQL / SPL text matches every positive sample, no negative, and only the attack events in the recorded data, in the Kusto emulator and a local Splunk | Log Analytics or Splunk-add-on behaviour exactly; false-positive rate in production; anything about YARA-L |
| `tests/evidence.md` per rule | the engine, dataset, counts and caveats of that run | anything about a production tenant |

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
mkdir -p data && curl -sSfL -o data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python -m dac validate --attack-bundle data/enterprise-attack.json
F="--rules-dir tests/fixtures/rules --customers-dir tests/fixtures/customers"
python -m dac $F schema-check --customer acme --siem sentinel
python -m dac $F gate --customer acme --siem sentinel --report-only
python -m dac $F coverage --customer acme
python -m dac $F plan --siem secops
# Engine tests (needs Docker; see docs/components/engine-tests.md)
docker run -d -e ACCEPT_EULA=Y -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
python -m harness fetch && python -m harness run --engine kusto
```

## Docs
- Components: [validation](docs/components/validation.md),
  [adapters](docs/components/adapters.md),
  [schema check](docs/components/schema-check.md),
  [log-source gate](docs/components/log-source-gate.md),
  [coverage](docs/components/coverage.md),
  [engine tests](docs/components/engine-tests.md),
  [CI/CD](docs/components/ci.md)
- Decisions: [docs/decisions/](docs/decisions/)
- Templates for every rule: [attack doc](templates/attack-doc.md),
  [rule doc](templates/rule-doc.md)
- Claude Code skills used to build this: [docs/skills.md](docs/skills.md)
- Build history: [BUILD_LOG.md](BUILD_LOG.md)
