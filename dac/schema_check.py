"""Schema check: does the data a rule needs exist, recently, with the fields it reads?

For one rule, one SIEM and one customer, each entry in the rule's
``required_fields`` (table / source / log type -> fields) is compared
with what is observed, from the first of these that is available:

1. a live probe of the customer's SIEM (adapter.probe), when the
   adapter's read-only credentials are set;
2. a schema file the customer sent, customers/<id>/schemas/<siem>/<name>.yaml.

With neither, the entry is ``not_checked`` and the gate falls back to a
human confirmation. See docs/components/schema-check.md and
docs/decisions/005-schema-check.md.
"""

from dataclasses import dataclass, field

from .adapters import ObservedSchema, ProbeError, SiemAdapter
from .rules import Customer, Rule, load_yaml, schema_file_name

OK = "ok"
MISSING_TABLE = "missing_table"
NO_RECENT_DATA = "no_recent_data"
MISSING_FIELDS = "missing_fields"
NOT_CHECKED = "not_checked"


@dataclass
class TableCheck:
    siem: str
    name: str
    status: str
    basis: str                                  # "probe", "customer-schema" or "none"
    missing_fields: list[str] = field(default_factory=list)
    note: str = ""

    def describe(self) -> str:
        if self.status == OK:
            return f"{self.name}: present, all required fields seen ({self.basis})"
        if self.status == MISSING_TABLE:
            return f"{self.name}: not found in {self.siem} ({self.basis})"
        if self.status == NO_RECENT_DATA:
            return f"{self.name}: no events in the last 24h ({self.basis}){': ' + self.note if self.note else ''}"
        if self.status == MISSING_FIELDS:
            return f"{self.name}: missing fields {', '.join(self.missing_fields)} ({self.basis})"
        if self.basis == "probe failed":
            return f"{self.name}: not checked, probe failed: {self.note}"
        return f"{self.name}: not checked (no probe credentials and no schema from the customer)"


def customer_schema(customer: Customer, siem: str, name: str) -> ObservedSchema | None:
    path = customer.schemas_dir / siem / schema_file_name(name)
    if not path.exists():
        return None
    data = load_yaml(path)
    note = f"sent by {data.get('provided_by', 'unknown')} on {data.get('provided_on', 'unknown date')}"
    return ObservedSchema(name, "customer-schema", exists=True, fields=set(data.get("fields", [])),
                          recent_events=None, note=note)


def observe(siem: str, name: str, customer: Customer, adapter: SiemAdapter | None,
            cache: dict | None = None) -> ObservedSchema | None:
    """Probe if possible, else the customer's schema file, else None. Probes are cached per run."""
    if adapter is not None and adapter.has_probe_credentials():
        key = (customer.id, siem, name)
        if cache is None or key not in cache:
            observed = adapter.probe(name)
            if cache is None:
                return observed
            cache[key] = observed
        return cache[key]
    return customer_schema(customer, siem, name)


def compare(siem: str, name: str, required: list[str], observed: ObservedSchema | None) -> TableCheck:
    if observed is None:
        return TableCheck(siem, name, NOT_CHECKED, "none")
    if observed.exists is False:
        return TableCheck(siem, name, MISSING_TABLE, observed.basis, note=observed.note)
    if observed.recent_events == 0:
        return TableCheck(siem, name, NO_RECENT_DATA, observed.basis, note=observed.note)
    if observed.fields is None:
        return TableCheck(siem, name, NOT_CHECKED, observed.basis, note=observed.note)
    missing = [f for f in required if f not in observed.fields]
    if missing:
        return TableCheck(siem, name, MISSING_FIELDS, observed.basis, missing, note=observed.note)
    return TableCheck(siem, name, OK, observed.basis, note=observed.note)


def check_rule(rule: Rule, siem: str, customer: Customer, adapter: SiemAdapter | None = None,
               cache: dict | None = None) -> list[TableCheck]:
    checks = []
    for name, fields in rule.required_fields(siem).items():
        try:
            observed = observe(siem, name, customer, adapter, cache)
        except ProbeError as exc:
            # A failed probe is reported, never treated as a pass; the gate
            # then needs a human confirmation, as if no probe existed.
            checks.append(TableCheck(siem, name, NOT_CHECKED, "probe failed", note=str(exc)))
            continue
        checks.append(compare(siem, name, fields, observed))
    return checks
