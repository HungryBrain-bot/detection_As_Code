# Claude Code skills in this repo

This repo is built with Claude Code, and three project skills in
`.claude/skills/` encode how work is done here. A skill is a Markdown
file with a trigger description; Claude Code loads it when a task
matches, so the same procedure is followed every time without being
re-explained.

| Skill | Triggers when | What it enforces |
|---|---|---|
| [`build-and-document`](../.claude/skills/build-and-document/SKILL.md) | building or changing pipeline code or making a design decision | tests with code; component doc (what / how / why / advantages / limits) updated; ADR for real decisions; CLAUDE.md and BUILD_LOG.md kept current |
| [`new-detection`](../.claude/skills/new-detection/SKILL.md) | adding or changing a rule | attack doc first, then rule, samples with provenance labels, evidence, rule doc; validate, gate and plan before the PR |
| [`log-source-gate`](../.claude/skills/log-source-gate/SKILL.md) | a deploy is blocked, a team confirms a source, a team or source is added | how to read the gate output, record a real confirmation, add sources and teams, switch to email |

## Why skills, and not just a CONTRIBUTING file
CONTRIBUTING.md is read once, if at all. A skill is pulled in at the
moment the matching work starts, so the checklist is applied, not
remembered. The repo-wide rules that apply to every task stay in
CLAUDE.md; skills hold the procedures that apply only to one kind of
task.

## How they connect to CI
Skills tell the author what to do; CI checks the parts that can be
checked mechanically (doc sections filled, evidence file present,
ATT&CK IDs real, log sources confirmed). Neither checks that a doc is
correct or a source is real; that is review.

## Same pattern as the attack graph project
`attackKnowledgeGraph` uses the same layout: `build-and-document` and
`attack-pattern-doc` there are the models for `build-and-document` and
`new-detection` here.
