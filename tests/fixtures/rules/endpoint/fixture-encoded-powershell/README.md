# Fixture: encoded PowerShell command line

Pipeline test fixture. The sections below are short on purpose; they
exist so the doc-completeness check has a passing example.

## Hypothesis
Fixture text: an attacker hides a PowerShell payload with -EncodedCommand.

## Data sources
Fixture text: process creation with command line.

## Detection logic
Fixture text: PowerShell image plus an encoded-command switch.

## Why this logic
Fixture text: not a reviewed choice.

## False positives
Fixture text: management tools that use encoded commands.

## Tuning
Fixture text: none.

## Test evidence
Fixture text: none; this rule is never run against data.

## Blind spots
Fixture text: shortened switches and renamed binaries.

## References
Fixture text: none.
