# <Rule name>

<!-- Copy to detections/<track>/<folder>/README.md. Every "## " section
     below is required and checked by `python -m dac validate`; a section
     that is empty or contains TODO fails CI. -->

ATT&CK / OWASP: <IDs> · Severity: <severity> · Status: <status> · Targets: <sentinel, splunk, secops>

## Hypothesis
One paragraph: if the adversary does X, we expect to see Y in source Z.

## Data sources
Log source IDs from log_sources.yaml, the tables / sourcetypes / log
types used per SIEM, the logging configuration the rule depends on
(e.g. Sysmon config, command-line auditing, 4104), and what happens to
the rule if that source is missing.

## Detection logic
The query for each SIEM, then a line-by-line explanation of each filter
and why it is there. Note where the SIEM versions differ and why.

## Why this logic
Why this approach and not the alternatives (a broader or narrower
match, a threshold, a baseline, a different data source). Say what
each alternative would catch or miss that this one does not. This is
the section that answers "why is this the best fit".

## False positives
Known benign causes, each with whether it is excluded and how.

## Tuning
What was changed after running against the negative samples, and why.
What a production deployment would still need to tune (allowlists,
thresholds, schedule).

## Test evidence
Dataset and file for each sample, positive and negative row counts,
the date run and the engine used, and a link to tests/evidence.md.
Label every sample as recorded or hand-written.

## Blind spots
What this rule will miss: obfuscation, alternative tooling, other data
sources, attacker log tampering.

## References
Primary sources only, each with URL and the date fetched.
