"""Per-customer detection coverage: Navigator layers plus a one-page summary.

Outputs, in reports/coverage/<customer>/:

- attack-layer.json  ATT&CK Navigator layer (enterprise-attack)
- atlas-layer.json   layer for MITRE ATLAS techniques (LLM rules), only if any
- summary.md         table for management: technique, rule, status, why

A technique is **active** only when at least one of its rules passed the
log-source gate (probe or confirmation) on at least one SIEM the
customer runs. Rules that apply to the customer but are blocked are
shown as **blocked**, in a different colour, and are not counted as
coverage. See docs/decisions/006-coverage-reporting.md.

What this does not measure: whether a rule catches the technique in
practice. One rule usually detects one or two ways of doing a technique,
not all of them.
"""

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

from .gate import GateResult
from .rules import REPO_ROOT, Customer, Rule

COVERAGE_DIR = REPO_ROOT / "reports" / "coverage"

ACTIVE, BLOCKED = "active", "blocked"
COLOURS = {ACTIVE: "#31a354", BLOCKED: "#fdae61"}
SCORES = {ACTIVE: 2, BLOCKED: 1}

# ATT&CK enterprise tactic order, for the summary table.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]

LAYER_VERSIONS = {"layer": "4.5", "navigator": "5.1.0"}  # Navigator layer format; not checked against a live Navigator.


@dataclass
class RuleStatus:
    rule: Rule
    status: str                                    # active / blocked
    active_on: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def rule_statuses(customer: Customer, rules: list[Rule], gate_results: list[GateResult]) -> list[RuleStatus]:
    """One status per applicable rule, from the gate results for the customer's SIEMs."""
    statuses = []
    for rule in customer.applicable_rules(rules):
        active_on, reasons = [], []
        for result in gate_results:
            if result.customer != customer.id or result.siem not in rule.targets():
                continue
            if rule.id in result.allowed:
                active_on.append(result.siem)
            elif rule.id in result.blocked:
                reasons += [f"{result.siem}: {r}" for r in result.blocked[rule.id]]
        if not active_on and not reasons:
            reasons = ["targets none of the customer's SIEMs"]
        statuses.append(RuleStatus(rule, ACTIVE if active_on else BLOCKED, active_on, reasons))
    return statuses


def _technique_entries(statuses: list[RuleStatus], key: str) -> list[dict]:
    """Merge rule statuses per technique: active wins over blocked."""
    merged: dict[tuple[str, str], dict] = {}
    for st in statuses:
        mapping = st.rule.data["mapping"]
        if key == "attack":
            pairs = [(t, tac) for t in mapping.get("attack", {}).get("techniques", [])
                     for tac in mapping["attack"]["tactics"]]
        else:
            pairs = [(t, None) for t in mapping.get("atlas", [])]
        for technique, tactic in pairs:
            entry = merged.setdefault((technique, tactic), {"status": BLOCKED, "rules": []})
            if st.status == ACTIVE:
                entry["status"] = ACTIVE
            label = f"{st.rule.name} ({st.status}{': ' + ', '.join(st.active_on) if st.active_on else ''})"
            entry["rules"].append(label)
    entries = []
    for (technique, tactic), entry in sorted(merged.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        item = {"techniqueID": technique, "score": SCORES[entry["status"]],
                "color": COLOURS[entry["status"]], "comment": "; ".join(entry["rules"]),
                "enabled": True}
        if tactic:
            item["tactic"] = tactic
        entries.append(item)
    return entries


def navigator_layer(customer: Customer, statuses: list[RuleStatus], domain: str, key: str,
                    today: dt.date, attack_version: str | None = None) -> dict | None:
    techniques = _technique_entries(statuses, key)
    if not techniques:
        return None
    versions = dict(LAYER_VERSIONS)
    if attack_version and key == "attack":
        versions["attack"] = attack_version
    return {
        "name": f"{customer.name} detection coverage ({today.isoformat()})",
        "versions": versions,
        "domain": domain,
        "description": ("Green: a rule is deployable, its log sources passed the gate. "
                        "Orange: a rule exists but is blocked on log sources; not counted as coverage."),
        "techniques": techniques,
        "legendItems": [
            {"label": "Active: rule deployable, data confirmed", "color": COLOURS[ACTIVE]},
            {"label": "Blocked: rule exists, log source not confirmed", "color": COLOURS[BLOCKED]},
        ],
        "hideDisabled": False,
    }


def summary_markdown(customer: Customer, statuses: list[RuleStatus], today: dt.date) -> str:
    def order(st: RuleStatus):
        tactics = st.rule.data["mapping"].get("attack", {}).get("tactics", [])
        positions = [TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER]
        return (min(positions) if positions else len(TACTIC_ORDER), st.rule.name)

    active = [s for s in statuses if s.status == ACTIVE]
    techniques_active = {t for s in active for t in s.rule.data["mapping"].get("attack", {}).get("techniques", [])}
    lines = [
        f"# Detection coverage: {customer.name}",
        "",
        f"As of {today.isoformat()}. SIEMs: {', '.join(customer.siems)}.",
        "",
        f"**{len(active)} of {len(statuses)} applicable rules are active**, covering "
        f"{len(techniques_active)} ATT&CK technique(s). Blocked rules are listed with the reason and "
        "are not counted.",
        "",
        "| Tactic | Technique | Rule | Tier | Status | Detail |",
        "|---|---|---|---|---|---|",
    ]
    for st in sorted(statuses, key=order):
        mapping = st.rule.data["mapping"]
        tactic = ", ".join(mapping.get("attack", {}).get("tactics", [])) or "-"
        technique = ", ".join(mapping.get("attack", {}).get("techniques", [])
                              + [f"{i}:2025" for i in mapping.get("owasp_llm_2025", [])]
                              + [f"{i}:2026" for i in mapping.get("owasp_llm_2026", [])]
                              + mapping.get("atlas", []))
        detail = (f"active on {', '.join(st.active_on)}" if st.status == ACTIVE
                  else "; ".join(st.reasons))
        lines.append(f"| {tactic} | {technique} | {st.rule.name} | {st.rule.tier} | "
                     f"{st.status} | {detail.replace('|', '/')} |")
    lines += [
        "",
        "## How to read this",
        "",
        "- **Active** means the rule can be deployed: its log sources were confirmed, by a live "
        "schema probe or by the owning team. It does not mean the rule has caught this technique "
        "in this environment.",
        "- One rule usually detects one or two ways of performing a technique, not every way. "
        "A coloured technique is not a fully covered technique.",
        "- LLM application rules map to OWASP LLM Top 10 (2025 and 2026, which number the same "
        "risks differently) and MITRE ATLAS, not ATT&CK, and appear in the ATLAS layer.",
    ]
    return "\n".join(lines) + "\n"


def write_coverage(customer: Customer, rules: list[Rule], gate_results: list[GateResult],
                   out_dir: Path | None = None, today: dt.date | None = None,
                   attack_version: str | None = None) -> list[Path]:
    today = today or dt.date.today()
    out_dir = (out_dir or COVERAGE_DIR) / customer.id
    out_dir.mkdir(parents=True, exist_ok=True)
    statuses = rule_statuses(customer, rules, gate_results)
    written = []
    for filename, domain, key in (("attack-layer.json", "enterprise-attack", "attack"),
                                  ("atlas-layer.json", "atlas", "atlas")):
        layer = navigator_layer(customer, statuses, domain, key, today, attack_version)
        if layer:
            path = out_dir / filename
            path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
            written.append(path)
    summary = out_dir / "summary.md"
    summary.write_text(summary_markdown(customer, statuses, today), encoding="utf-8")
    written.append(summary)
    return written
