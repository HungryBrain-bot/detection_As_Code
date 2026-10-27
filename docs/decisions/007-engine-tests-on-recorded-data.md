# 007. Test rules in local engines against recorded open-source data

## Status
Accepted (2026-10-27)

## Context
Every rule needs evidence from an actual engine run (CLAUDE.md,
Conventions). The plan was a free Azure Data Explorer cluster; the
owner cannot create ADX or Log Analytics resources and asked instead
for the rules to be checked against open-source sample logs, rather
than shipping them as "not run" and `experimental`.

## Decision
- Run KQL in the Azure Data Explorer emulator (Kustainer) and SPL in a
  Splunk Enterprise container, both local Docker images. YARA-L is not
  run; there is no engine for it outside SecOps, and evidence says so.
- Use recorded data from OTRF Security-Datasets (MIT), pinned by commit
  and SHA-256, loaded in full (attack plus background), and rebuilt into
  each SIEM's storage shape by one documented mapping module.
- Keep the rule's own positive and negative samples, labelled recorded
  or hand-written, and require positives to match and negatives not to.
- Commit the result of each run (`tests/results/<engine>.json`) and run
  the KQL tests in CI on every PR against the committed counts.
- A rule with passing engine evidence on Sentinel and Splunk moves to
  `status: test` (deployed enabled), not `stable`: `stable` waits for a
  live SIEM run and a production false-positive baseline.

## Alternatives considered
- **Hand-written samples only, evaluated in Python.** Cheap, but tests
  my reimplementation of the query, not the query; and hand-written
  data only contains the mistakes I thought of.
- **Translate rules to Sigma and run pySigma / a Sigma backend.**
  Tests a translation, not the deployed query, and Sigma is the last
  item in the cut order.
- **EVTX-ATTACK-SAMPLES / Splunk attack_data.** EVTX-ATTACK-SAMPLES had
  no licence file when checked (2026-10-27), so it is not reused.
  Splunk attack_data (Apache 2.0) is a good second source for later
  rules; OTRF covered A1-A4 with both attack and background events.
- **Wait for a live tenant.** Leaves every rule unverified for the
  whole time box.

## Consequences
- Evidence is real but not production: lab hosts, two engines that are
  close to, not the same as, the deployed SIEMs
  (docs/components/engine-tests.md lists the gaps).
- SecOps rules deploy with `status: test` without having run anywhere.
  Creating a rule through the SecOps adapter does not turn on live
  detection or alerting (dac/adapters/secops.py), so
  an untested SecOps rule cannot page anyone, but it can silently match
  nothing if a UDM field name is wrong.
- CI gains a job that pulls a container image; the image is pinned by
  digest.
