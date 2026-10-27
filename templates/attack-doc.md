# <Attack name> (<ATT&CK / OWASP ID>)

<!-- Copy to detections/<track>/<folder>/attack.md. Every "## " section
     below is required and checked by `python -m dac validate`; a section
     that is empty or contains TODO fails CI. Write it while building the
     rule, not afterwards. Paraphrase sources; never invent campaign
     details, dates or quotes. -->

## What the attack is
Two or three sentences: what the adversary achieves with this
technique, and why it matters to a defender.

## How the attack happens
Step by step, from the attacker's side: the preconditions, the commands
or API calls, what changes on the host / tenant / application, and what
the attacker does next. Name the real tools that do it.

## Real-world use
At least one public, fetched, dated report of this technique in use,
with the group or campaign named as the source names it. For the
identity and LLM tracks this is where "trending" has to be backed: a
recent report, not an opinion. If no report was fetched, say so.

## What it leaves in the logs
The specific events and fields the attack produces (event IDs, table
and column names, UDM fields), and which of them an attacker can
suppress or spoof.

## Prerequisites
What the attacker needs first (access level, privileges, a consented
app, a reachable endpoint), and which earlier technique usually
provides it.

## Mapping
ATT&CK technique and tactic, or OWASP LLM Top 10 (2025) and MITRE ATLAS
IDs for the LLM track. Say why this ID and not its neighbor.

## References
Primary sources only, each with URL and the date fetched.
