# Engine tests on recorded attack data

Code: `harness/` (`python -m harness`). Decision record:
[ADR 007](../decisions/007-engine-tests-on-recorded-data.md).

## What it does
Runs each rule's real query in a real query engine, against:

1. the rule's own samples (`tests/positive.json` must all match,
   `tests/negative.json` must not), and
2. every event of a set of recorded, open-source attack datasets
   (attack activity plus the host's background noise), recording each
   row the rule returns.

The output is `tests/results/<engine>.json` in the rule folder, and
`tests/evidence.md` is written from it. No cloud account is needed.

| Rule language | Engine | How faithful |
|---|---|---|
| KQL (Sentinel) | Azure Data Explorer emulator ("Kustainer"), Docker image `mcr.microsoft.com/azuredataexplorer/kustainer-linux` | Real KQL engine. ADX, not Log Analytics: a function that exists only in Log Analytics fails here, visibly. Tables are created from `schemas/reference/sentinel/`. |
| SPL (Splunk) | Splunk Enterprise in Docker (`splunk/splunk`, local trial licence) | Real Splunk search. The Windows add-on is not installed (Splunkbase needs a login); `harness/engines.py` installs a minimal XmlWinEventLog extraction instead. |
| YARA-L (SecOps) | none | No YARA-L engine exists outside a SecOps tenant. Not run; evidence says so. |

## How it works
1. `python -m harness fetch` downloads each dataset in
   `harness/datasets.yaml` from GitHub at a pinned commit, checks its
   SHA-256, and extracts the JSON into `data/datasets/` (gitignored).
   Zip members are written by base name only.
2. `harness/mapping.py` rebuilds each recorded event in the shape the
   SIEM stores it:
   - Security channel -> a `SecurityEvent` row (EventData fields become
     columns of the same name, which is how SecurityEvent names them);
   - Sysmon and other channels -> an `Event` row with `EventData` XML in
     the shape Microsoft's Sysmon parser reads;
   - for Splunk -> Windows event XML, sent through HEC with
     `sourcetype=XmlWinEventLog` and `source=XmlWinEventLog:<channel>`.
   Field values are copied unchanged. What the mapping approximates is
   listed in its docstring.
3. `python -m harness run --engine kusto|splunk [--rule A1] [--write]`
   resets the engine, loads the positives and runs the query, loads the
   negatives alone and runs it, then loads all datasets the rule lists
   in `tests/datasets.yaml` and runs it once more.
4. Without `--write` it also compares the dataset match count with the
   committed `tests/results/<engine>.json`, so CI notices when a rule or
   the data changes what it catches.

## Why this method
- The owner has no Azure Data Explorer cluster, Log Analytics workspace
  or Splunk licence. Both engines run locally in containers, so the
  queries that will be deployed are the queries that were tested,
  unmodified.
- Recorded data, not only hand-written samples: OTRF Security-Datasets
  are real Windows events from a lab domain while an attack tool ran,
  including the host's own background. That background is what found
  the tuning problems documented in each rule (`ClipRenew.exe -e`,
  Defender writing a Run key, `reg export HKLM\SYSTEM\...`).
- Samples and datasets together: the samples cover branches the data
  does not (no recorded certutil or curl download exists in these
  datasets), and their provenance label says which is which.
- Running the same rule in two engines catches query-language mistakes
  the offline validator cannot. It did once: the validator's quote
  checker misread KQL verbatim strings and YARA-L regex literals, and
  was fixed (`check_balanced` now takes per-language string rules).

## Advantages
- Evidence is reproducible: pinned commit, SHA-256, engine version and
  date in every result file; one command reruns it.
- The KQL run is in CI (`engine-kusto` job) on every PR, so a change
  that stops a positive matching, or starts matching a negative, fails
  the PR.
- No secrets: the containers are local and throwaway.

## Limits
- Lab data is not production. A rule that is silent on 45,370 lab
  events can still be noisy in a real estate; false-positive rates are
  not measured here.
- ADX is not Log Analytics, and the Splunk extraction is not the
  Windows add-on. A rule can pass here and still need a fix in the real
  SIEM; the first live run is the real test (CLAUDE.md, "not verified").
- The Sentinel tables come from reference schemas fetched through a
  summarising tool; recorded fields with no matching column are dropped
  on load and listed in the result file.
- YARA-L is not run at all.
- The Splunk run is local only, not in CI: it needs a several-GB image
  and a licence acceptance.

## Running it locally
```bash
docker run -d --name kustainer -e ACCEPT_EULA=Y -p 8080:8080 \
  mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
docker run -d --name splunk -p 8089:8089 -p 8088:8088 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD=<local password> -e SPLUNK_HEC_TOKEN=<local uuid> \
  splunk/splunk:latest
python -m harness fetch
python -m harness run --engine kusto
DAC_SPLUNK_PASSWORD=<local password> DAC_SPLUNK_HEC_TOKEN=<local uuid> DAC_SPLUNK_INSECURE=1 \
  python -m harness run --engine splunk
```
`ACCEPT_EULA` and the two Splunk `--accept-*` options accept the
vendors' licence terms for these test containers; whoever runs them is
accepting those terms. `DAC_SPLUNK_INSECURE=1` skips TLS verification
for the container's self-signed certificate and is refused for any host
other than localhost. Settings: `DAC_KUSTO_URL` (default
`http://localhost:8080`), `DAC_SPLUNK_URL` (default
`https://localhost:8089`), `DAC_SPLUNK_HEC_URL` (default
`https://localhost:8088`), `DAC_SPLUNK_USER` (default `admin`).

## Adding a dataset or a rule
- Dataset: add it to `harness/datasets.yaml` with commit, path,
  SHA-256 and licence. Only datasets whose licence allows reuse; OTRF
  is MIT. A dataset with no licence file (for example
  EVTX-ATTACK-SAMPLES at the time of writing) is not used.
- Rule: list dataset ids in `tests/datasets.yaml`, run with `--write`,
  then write `tests/evidence.md` from the result.
