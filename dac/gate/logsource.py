"""Pre-deploy log-source gate, per customer and SIEM.

A rule may only be deployed to a customer's SIEM if every log source it
declares passes for that customer and SIEM. A source passes in one of
two ways (ADR 003 and its 2026-10-27 amendment, ADR 005):

1. **Live probe.** When the adapter's read-only credentials are set,
   the schema check queries the SIEM. If every table the rule reads
   from this source exists, has events in the last 24h and has every
   required field, the source is auto-confirmed with no human step. If
   the probe finds a gap, the rule is blocked even if a human
   confirmation exists: the live data wins over a person's word.
2. **Human confirmation**, when no probe can run: a committed file
   customers/<id>/confirmations/<siem>/<log_source>.yaml:

       log_source: windows-process-creation
       siem: sentinel
       confirmed_by: Endpoint Engineering (name)
       confirmed_on: 2026-10-27
       evidence: Free text, e.g. "Event has Sysmon EventID 1 rows in the last 24h"

   Confirmations expire after CONFIRMATION_MAX_AGE_DAYS. If the customer
   sent a schema file for a table and it lacks required fields, the
   rule is blocked regardless.

For every source that does not pass, the owning team gets one reminder
listing what is missing and the rules waiting on it, and asking for the
actual table and schema if their data lands somewhere else.
"""

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters import SiemAdapter
from ..rules import REPO_ROOT, Customer, Rule, load_yaml
from ..schema_check import OK, TableCheck, check_rule
from .notifier import Notice, select_notifier

NOTIFICATIONS_DIR = REPO_ROOT / "reports" / "notifications"
CONFIRMATION_MAX_AGE_DAYS = 90

# How "your data may be somewhere else" reads for each SIEM's data model.
ELSEWHERE = {
    "sentinel": "a different table (for example everything forwarded to Syslog or CommonSecurityLog)",
    "splunk": "a different index, source or sourcetype",
    "secops": "a different log type, or different UDM field mappings from your parser",
}


@dataclass
class GateResult:
    customer: str
    siem: str
    allowed: list[str] = field(default_factory=list)                 # rule ids
    blocked: dict[str, list[str]] = field(default_factory=dict)       # rule id -> reasons
    auto_confirmed: dict[str, list[str]] = field(default_factory=dict)  # rule id -> sources passed by probe
    checks: dict[str, list[TableCheck]] = field(default_factory=dict)   # rule id -> schema checks
    deliveries: list[str] = field(default_factory=list)              # where reminders went

    @property
    def passed(self) -> bool:
        return not self.blocked


def confirmation_problem(siem: str, source_id: str, today: dt.date, confirmations_dir: Path) -> str | None:
    """None if the source has a current human confirmation for this SIEM, else why not."""
    path = confirmations_dir / siem / f"{source_id}.yaml"
    if not path.exists():
        return f"{source_id}: no confirmation for {siem}"
    data = load_yaml(path)
    if data.get("log_source") != source_id or data.get("siem") != siem:
        return f"{source_id}: {path.name} does not match its folder (log_source/siem fields)"
    if not str(data.get("confirmed_by") or "").strip():
        return f"{source_id}: confirmation has no confirmed_by"
    confirmed_on = data.get("confirmed_on")
    if not isinstance(confirmed_on, dt.date):
        return f"{source_id}: confirmed_on must be a YYYY-MM-DD date"
    if confirmed_on > today:
        return f"{source_id}: confirmed_on is in the future"
    age = (today - confirmed_on).days
    if age > CONFIRMATION_MAX_AGE_DAYS:
        return f"{source_id}: confirmation is {age} days old (max {CONFIRMATION_MAX_AGE_DAYS})"
    return None


def source_decision(source_id: str, siem: str, catalogue: dict, checks: list[TableCheck],
                    customer: Customer, today: dt.date) -> tuple[bool, list[str], bool]:
    """(passed, problems, auto_confirmed) for one log source of one rule."""
    names = set(catalogue[source_id]["siem"].get(siem, []))
    mine = [c for c in checks if c.name in names]
    probed = [c for c in mine if c.basis == "probe"]
    if probed:
        gaps = [f"{source_id}: {c.describe()}" for c in probed if c.status != OK]
        return (not gaps, gaps, not gaps)
    problems = [f"{source_id}: {c.describe()}" for c in mine
                if c.basis == "customer-schema" and c.status != OK]
    human = confirmation_problem(siem, source_id, today, customer.confirmations_dir)
    if human:
        problems.append(human)
    return (not problems, problems, False)


def _reminder(customer: Customer, siem: str, team_id: str, sources: dict[str, dict],
              catalogue: dict, rules_by_id: dict[str, Rule]) -> Notice:
    team = customer.teams.get(team_id, {})
    lines = [
        f"Detection rules are waiting to be deployed to {customer.name}'s {siem}. Before they go "
        f"out, please check these log sources are onboarded in {siem}, with events arriving and "
        "the fields below present:",
        "",
    ]
    for source_id, info in sorted(sources.items()):
        lines.append(f"- {source_id}: {catalogue[source_id]['description']}")
        lines.append(f"  Expected in {siem} as: {', '.join(catalogue[source_id]['siem'].get(siem, []))}")
        for problem in sorted(set(info["problems"])):
            lines.append(f"  Found: {problem.split(': ', 1)[1]}")
        for rule_id in info["rules"]:
            rule = rules_by_id[rule_id]
            needed = {n: f for n, f in rule.required_fields(siem).items()
                      if n in catalogue[source_id]["siem"].get(siem, [])}
            detail = "; ".join(f"{n}: {', '.join(f)}" for n, f in needed.items())
            lines.append(f"  Needed by: {rule.name} ({rule_id})" + (f", reads {detail}" if detail else ""))
    lines += [
        "",
        "If this data is already collected but lands in "
        f"{ELSEWHERE[siem]}, reply with where it lands and its schema (field names). We commit it to "
        f"customers/{customer.id}/schemas/{siem}/ and adapt the rule to it.",
        f"If it is onboarded as listed, confirm by committing customers/{customer.id}/confirmations/"
        f"{siem}/<log_source>.yaml (log_source, siem, confirmed_by, confirmed_on, evidence). "
        "See docs/components/log-source-gate.md.",
        "Until then these rules are not deployed.",
    ]
    return Notice(
        team_id=team_id,
        team_name=team.get("name", team_id),
        email=team.get("email") or "",
        siem=siem,
        subject=f"[detection-as-code] {customer.name}: check {len(sources)} log source(s) in {siem}",
        body="\n".join(lines),
    )


def run_gate(rules: list[Rule], siem: str, catalogue: dict, customer: Customer,
             today: dt.date | None = None, adapter: SiemAdapter | None = None,
             notifications_dir: Path | None = None, env: dict | None = None,
             notify: bool = True, probe_cache: dict | None = None, **notifier_kwargs) -> GateResult:
    """Gate the customer's applicable rules for one SIEM. `rules` is every rule in the repo."""
    today = today or dt.date.today()
    notifications_dir = (notifications_dir or NOTIFICATIONS_DIR) / customer.id
    result = GateResult(customer=customer.id, siem=siem)
    if siem not in customer.siems:
        return result
    applicable = [r for r in customer.applicable_rules(rules) if siem in r.targets()]
    rules_by_id = {rule.id: rule for rule in applicable}
    # team id -> source id -> {"rules": [...], "problems": [...]}
    waiting: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(lambda: {"rules": [], "problems": []}))
    cache = {} if probe_cache is None else probe_cache

    for rule in applicable:
        checks = check_rule(rule, siem, customer, adapter, cache)
        result.checks[rule.id] = checks
        reasons = []
        for source_id in rule.log_sources:
            passed, problems, auto = source_decision(source_id, siem, catalogue, checks, customer, today)
            if auto:
                result.auto_confirmed.setdefault(rule.id, []).append(source_id)
            if not passed:
                reasons += problems
                entry = waiting[catalogue[source_id]["owner"]][source_id]
                entry["rules"].append(rule.id)
                entry["problems"] += problems
        if reasons:
            result.blocked[rule.id] = reasons
        else:
            result.allowed.append(rule.id)

    if notify:
        for team_id, sources in sorted(waiting.items()):
            notice = _reminder(customer, siem, team_id, sources, catalogue, rules_by_id)
            notifier = select_notifier(notice, notifications_dir, env=env, **notifier_kwargs)
            result.deliveries.append(f"{team_id}: {notifier.send(notice)}")
    return result
