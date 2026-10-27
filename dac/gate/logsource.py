"""Pre-deploy log-source gate.

A rule may only be deployed to a SIEM if every log source it declares
has a current confirmation for that SIEM from the owning team. A
confirmation is a committed file, confirmations/<siem>/<log_source>.yaml:

    log_source: windows-process-creation
    siem: sentinel
    confirmed_by: Endpoint Engineering (name)
    confirmed_on: 2026-10-27
    evidence: Free text, e.g. "SysmonEvent has EventID 1 rows in the last 24h"

Confirmations expire after CONFIRMATION_MAX_AGE_DAYS, because a source
that was onboarded can later stop flowing.

For every source that is missing or expired, the owning team gets one
reminder listing the sources and the rules waiting on them, and those
rules are blocked. The gate checks that a person confirmed the source;
it does not check that the data is actually arriving. See
docs/decisions/003-log-source-gate.md.
"""

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..rules import REPO_ROOT, Rule, load_yaml
from .notifier import Notice, select_notifier

CONFIRMATIONS_DIR = REPO_ROOT / "confirmations"
NOTIFICATIONS_DIR = REPO_ROOT / "reports" / "notifications"
CONFIRMATION_MAX_AGE_DAYS = 90


@dataclass
class GateResult:
    siem: str
    allowed: list[str] = field(default_factory=list)            # rule ids
    blocked: dict[str, list[str]] = field(default_factory=dict)  # rule id -> reasons
    deliveries: list[str] = field(default_factory=list)         # where reminders went

    @property
    def passed(self) -> bool:
        return not self.blocked


def confirmation_problem(siem: str, source_id: str, today: dt.date,
                         confirmations_dir: Path = CONFIRMATIONS_DIR) -> str | None:
    """None if the source has a current confirmation for this SIEM, else why not."""
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


def _reminder(siem: str, team_id: str, team: dict, sources: dict[str, list[str]],
              catalogue: dict, rules_by_id: dict[str, Rule]) -> Notice:
    lines = [
        f"Detection rules are waiting to be deployed to {siem}. Before they go out, please "
        f"confirm that these log sources are onboarded in {siem} and that events are arriving:",
        "",
    ]
    for source_id, rule_ids in sorted(sources.items()):
        lines.append(f"- {source_id}: {catalogue[source_id]['description']}")
        tables = ", ".join(catalogue[source_id]["siem"].get(siem, []))
        lines.append(f"  Expected in {siem} as: {tables}")
        for rule_id in rule_ids:
            lines.append(f"  Needed by: {rules_by_id[rule_id].name} ({rule_id})")
    lines += [
        "",
        f"To confirm, commit confirmations/{siem}/<log_source>.yaml with log_source, siem, "
        "confirmed_by, confirmed_on and evidence. See docs/components/log-source-gate.md.",
        "Until then these rules are not deployed.",
    ]
    return Notice(
        team_id=team_id,
        team_name=team.get("name", team_id),
        email=team.get("email") or "",
        siem=siem,
        subject=f"[detection-as-code] Confirm {len(sources)} log source(s) in {siem}",
        body="\n".join(lines),
    )


def run_gate(rules: list[Rule], siem: str, catalogue: dict, teams: dict,
             today: dt.date | None = None,
             confirmations_dir: Path | None = None,
             notifications_dir: Path | None = None,
             env: dict | None = None, notify: bool = True, **notifier_kwargs) -> GateResult:
    today = today or dt.date.today()
    confirmations_dir = confirmations_dir or CONFIRMATIONS_DIR
    notifications_dir = notifications_dir or NOTIFICATIONS_DIR
    result = GateResult(siem=siem)
    rules_by_id = {rule.id: rule for rule in rules}
    # team id -> source id -> rule ids waiting on it
    waiting: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    for rule in rules:
        if siem not in rule.targets():
            continue
        reasons = []
        for source_id in rule.log_sources:
            problem = confirmation_problem(siem, source_id, today, confirmations_dir)
            if problem:
                reasons.append(problem)
                waiting[catalogue[source_id]["owner"]][source_id].append(rule.id)
        if reasons:
            result.blocked[rule.id] = reasons
        else:
            result.allowed.append(rule.id)

    if notify:
        for team_id, sources in sorted(waiting.items()):
            notice = _reminder(siem, team_id, teams.get(team_id, {}), sources, catalogue, rules_by_id)
            notifier = select_notifier(notice, notifications_dir, env=env, **notifier_kwargs)
            result.deliveries.append(f"{team_id}: {notifier.send(notice)}")
    return result
