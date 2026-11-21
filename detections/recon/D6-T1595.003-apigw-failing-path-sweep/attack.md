# An agent sweeps an API's paths, on AWS API Gateway (T1595.003)

## What the attack is
Same attack as [D3](../D3-T1595.003-failing-path-sweep/attack.md):
requesting many candidate paths on an API to find the ones that exist
or answer differently, guessed from a word list or taken from a spec or
script. Here the API is published through Amazon API Gateway.

## How the attack happens
1. The tool picks a target domain and a list of candidate paths.
2. It requests them quickly, one after another, often with a baseline
   request to a path that cannot exist.
3. Most answers are 401, 403 or 404; the few that differ are what the
   tool reports.

## Real-world use
- Wiz (2026-10-22) saw an ARTEX agent send "more than 60 variations of
  SSO routes" in two minutes, with 401 and 403 answers in the sample
  lines (docs/threats/artex-phase2-recon.md). Wiz does not say the API
  was on AWS.
- **No fetched source shows ARTEX against an API on API Gateway.** This
  rule detects the behaviour there; it is not evidence that ARTEX does
  it on AWS.

## What it leaves in the logs
API Gateway access log lines (this project's JSON format) in
`AWSCloudWatch.Message`: `sourceIp`, `domainName`, `path`, `status`,
`userAgent`, `requestTimeEpoch`, `authorizerError`.

## Prerequisites
API Gateway access logging on every stage to cover, in the format of
docs/components/apigateway-access-log.md, shipped to Sentinel.

## Mapping
T1595.003 Active Scanning: Wordlist Scanning, as for D3. ID checked with
`python -m dac validate --attack-bundle` on 2026-11-21.

## References
- See README.md, References.
