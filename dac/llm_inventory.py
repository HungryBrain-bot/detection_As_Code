"""LLM log-source inventory: which LLM rules each customer app can feed.

Inputs (docs/components/llm-telemetry.md, ADR 008):

    llm_log_inventory.yaml        normalised schema + one entry per LLM log source
    customers/<id>/llm_apps.yaml  the customer's LLM apps and their sources
    rule.yaml `llm_telemetry`     columns an LLM rule needs populated

A rule that reads the normalised table needs more than the table to
exist: the columns it matches on must hold values. For each app and
rule, a needed column counts as fed when one of the app's sources maps a
field to it (`maps_to`) or the app fills it itself (`adds_columns`); a
content column (prompt, output or tool text) also needs the app's
`content_capture` on. A needed table other than the normalised one
(the canary registry) must come from a source whose `log_source` is
declared for that table.

What this does not check: that a source really emits what the inventory
says, or that an app's flags are true. Both are statements by people;
the inventory records which parts were checked against vendor pages.
"""

from dataclasses import dataclass, field
from pathlib import Path

from .rules import REPO_ROOT, SIEMS, Customer, Rule, load_yaml

INVENTORY_FILE = REPO_ROOT / "llm_log_inventory.yaml"
APPS_FILE = "llm_apps.yaml"
SOURCE_KEYS = ("name", "kind", "status", "log_source", "source_url", "fetched_on", "records",
               "maps_to", "gaps", "integration", "verified", "not_verified")
KINDS = ("logs", "alerts", "config")
STATUSES = ("recommended", "supported", "partial", "not-verified", "alerts-only")
RECORD_KEYS = ("prompts", "outputs", "tool_calls", "tool_arguments_and_results",
               "end_user_identity", "tokens", "guardrail_verdicts")
# Filled by the normaliser or Log Analytics for every row, whatever the source.
ALWAYS_FILLED = {"TimeGenerated", "LogSource", "Type"}


def load_inventory(path: Path = INVENTORY_FILE) -> dict:
    return load_yaml(path)


def load_apps(customer: Customer) -> dict:
    path = customer.folder / APPS_FILE
    return (load_yaml(path).get("apps") or {}) if path.exists() else {}


def validate_inventory(inventory: dict, catalogue: dict) -> list[str]:
    """Structure of llm_log_inventory.yaml against itself and log_sources.yaml."""
    errors = []
    table = inventory.get("normalised_table")
    columns = inventory.get("normalised_schema") or {}
    if not table or not columns:
        return ["llm_log_inventory.yaml needs normalised_table and normalised_schema"]
    for column, spec in columns.items():
        if not isinstance(spec, dict) or "from" not in spec or not isinstance(spec.get("content"), bool):
            errors.append(f"normalised_schema.{column}: needs `from` and a boolean `content`")
    for source_id, source in (inventory.get("sources") or {}).items():
        where = f"sources.{source_id}"
        missing = [k for k in SOURCE_KEYS if k not in source]
        if missing:
            errors.append(f"{where}: missing {missing}")
            continue
        if source["kind"] not in KINDS:
            errors.append(f"{where}: kind must be one of {KINDS}")
        if source["status"] not in STATUSES:
            errors.append(f"{where}: status must be one of {STATUSES}")
        if source["log_source"] not in catalogue:
            errors.append(f"{where}: log_source {source['log_source']} is not in log_sources.yaml")
        if not str(source["source_url"]).startswith("https://"):
            errors.append(f"{where}: source_url must be an https URL")
        missing_records = [k for k in RECORD_KEYS if k not in (source["records"] or {})]
        if missing_records:
            errors.append(f"{where}: records missing {missing_records}")
        unknown = sorted(set(source["maps_to"] or {}) - set(columns))
        if unknown:
            errors.append(f"{where}: maps_to names columns not in normalised_schema: {unknown}")
        siems = set(source["integration"] or {})
        if siems != set(SIEMS):
            errors.append(f"{where}: integration must say something for each of {list(SIEMS)}")
    return errors


def validate_apps(customer: Customer, inventory: dict) -> list[str]:
    """customers/<id>/llm_apps.yaml: sources exist, owner is a team, columns are real."""
    errors = []
    sources = inventory.get("sources") or {}
    columns = set(inventory.get("normalised_schema") or {})
    for app_id, app in load_apps(customer).items():
        where = f"{APPS_FILE} {app_id}"
        if app.get("owner") not in customer.teams:
            errors.append(f"{where}: owner {app.get('owner')!r} has no entry in teams.yaml")
        if not app.get("sources"):
            errors.append(f"{where}: lists no sources")
        errors += [f"{where}: unknown source {s}" for s in app.get("sources", []) if s not in sources]
        if not isinstance(app.get("content_capture"), bool):
            errors.append(f"{where}: content_capture must be true or false")
        errors += [f"{where}: adds_columns names unknown column {c}"
                   for c in app.get("adds_columns", []) if c not in columns]
    return errors


def validate_rule_telemetry(rule: Rule, inventory: dict) -> list[str]:
    """An LLM rule (one that reads the normalised table) must say which columns it needs populated."""
    table = inventory.get("normalised_table")
    reads = rule.required_fields("sentinel").get(table)
    needs = rule.data.get("llm_telemetry", {}).get("populated")
    if reads is None:
        return [] if needs is None else [f"llm_telemetry is set but the rule does not read {table}"]
    if not needs:
        return [f"reads {table} but has no llm_telemetry.populated (see llm-log-inventory skill)"]
    extra = [c for c in needs if c not in reads]
    return [f"llm_telemetry.populated names {extra}, not in required_fields[{table}]"] if extra else []


@dataclass
class Feed:
    app: str
    rule: Rule
    missing: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing


def check_feed(app_id: str, app: dict, rule: Rule, inventory: dict, catalogue: dict) -> Feed:
    table = inventory["normalised_table"]
    schema = inventory["normalised_schema"]
    sources = [inventory["sources"][s] for s in app.get("sources", []) if s in inventory["sources"]]
    fed = ALWAYS_FILLED | set(app.get("adds_columns", []))
    for source in sources:
        fed |= set(source.get("maps_to") or {})
    feed = Feed(app=app_id, rule=rule)
    for column in rule.data.get("llm_telemetry", {}).get("populated", []):
        if column not in fed:
            feed.missing.append(f"{column} (no source fills it)")
        elif schema[column]["content"] and not app.get("content_capture"):
            feed.missing.append(f"{column} (content capture is off)")
    tables_fed = {name for source in sources
                  for name in catalogue.get(source["log_source"], {}).get("siem", {}).get("sentinel", [])}
    for other in rule.required_fields("sentinel"):
        if other != table and other not in tables_fed:
            feed.missing.append(f"table {other} (no source of this app writes it)")
    return feed


def llm_rules(rules: list[Rule], inventory: dict) -> list[Rule]:
    table = inventory.get("normalised_table")
    return [r for r in rules if table in r.required_fields("sentinel")]


def report(customer: Customer, rules: list[Rule], inventory: dict, catalogue: dict) -> tuple[str, int]:
    """Markdown report and the number of (app, rule) pairs that cannot be fed."""
    apps = load_apps(customer)
    selected = llm_rules(rules, inventory)
    lines = [f"# LLM log-source inventory: {customer.name}", "",
             "Which LLM rules each app's telemetry can feed, from llm_log_inventory.yaml and "
             f"customers/{customer.id}/{APPS_FILE}. A rule is fed when every column in its "
             "`llm_telemetry.populated` is filled by one of the app's sources or by the app itself, "
             "with content capture on for prompt, output and tool text. This reads what the "
             "inventory and the app owner state; it does not observe the data.", ""]
    if not apps:
        lines.append(f"No {APPS_FILE} for this customer.")
        return "\n".join(lines) + "\n", 0
    gaps = 0
    for app_id, app in apps.items():
        lines += [f"## {app_id}", "", app.get("description", ""), "",
                  f"Sources: {', '.join(app.get('sources', []))}. "
                  f"Content capture: {'on' if app.get('content_capture') else 'off'}.", "",
                  "| Rule | Can feed | Missing |", "|---|---|---|"]
        for rule in selected:
            feed = check_feed(app_id, app, rule, inventory, catalogue)
            gaps += not feed.ok
            lines.append(f"| {rule.name} | {'yes' if feed.ok else 'no'} | {'; '.join(feed.missing) or '-'} |")
        source_gaps = [(s, g) for s in app.get("sources", []) for g in
                       (inventory["sources"].get(s, {}).get("gaps") or [])]
        if source_gaps:
            lines += ["", "Known gaps of these sources:"]
            lines += [f"- {s}: {g}" for s, g in source_gaps]
        lines.append("")
    return "\n".join(lines) + "\n", gaps
