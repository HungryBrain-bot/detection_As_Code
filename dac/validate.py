"""Offline checks on every rule folder. CI fails on any error.

Per rule:
1. rule.yaml matches schemas/rule.schema.json.
2. Rule ids are unique across the repo.
3. Every log source is in log_sources.yaml and is declared for every
   SIEM the rule targets.
4. Each SIEM query passes that adapter's check_query (structural only,
   see each adapter's docstring).
5. README.md (rule doc) and attack.md (attack doc) exist and every
   required heading has content that is not empty, has no TODO, and is
   not the template's own guidance text left unchanged. It cannot tell
   whether the content is correct or sourced; that is review's job.
6. tests/positive.json, tests/negative.json and tests/evidence.md exist.
7. With an ATT&CK STIX bundle: each technique exists, is not revoked or
   deprecated, and each tactic is one of its techniques' tactics.
8. Each SIEM block's required_fields only names tables / sources / log
   types declared for the rule's log sources, and, where a reference
   schema for that name is in schemas/reference/, every field exists in
   it. Where no reference schema exists, field names are not checked.

9. With MITRE ATLAS data (atlas-data `dist/v6/` YAML): each ATLAS ID
   exists and is not deprecated.
10. A rule that reads the normalised LLM table (LLMAppLog_CL) lists the
   columns it needs populated in `llm_telemetry` (ADR 008).

Per customer (validate_customers): SIEMs are known, included and
excluded rule ids exist, every owning team the customer's rules
need has an entry in its teams.yaml, and llm_apps.yaml (if present)
names known sources, columns and teams.

Repo-wide: llm_log_inventory.yaml is well formed (dac/llm_inventory.py).

Not checked here: that a query is valid in its language, or that it
fires on the positive samples. Those need a query engine; see
docs/components/engine-tests.md (`python -m harness`).
"""

import json
import re
from collections import Counter
from pathlib import Path

import jsonschema
import yaml

from .adapters import get_adapter
from .llm_inventory import load_inventory, validate_apps, validate_rule_telemetry
from .rules import REPO_ROOT, SIEMS, Customer, Rule, load_reference_schema

SCHEMA_FILE = REPO_ROOT / "schemas" / "rule.schema.json"
TEMPLATES_DIR = REPO_ROOT / "templates"

RULE_DOC_HEADINGS = [
    "Hypothesis", "Data sources", "Detection logic", "Why this logic",
    "False positives", "Tuning", "Test evidence", "Blind spots", "References",
]
ATTACK_DOC_HEADINGS = [
    "What the attack is", "How the attack happens", "Real-world use",
    "What it leaves in the logs", "Prerequisites", "Mapping", "References",
]
REQUIRED_TEST_FILES = ["positive.json", "negative.json", "evidence.md"]
PLACEHOLDER = re.compile(r"\bTODO\b|<fill in>", re.IGNORECASE)


def load_schema() -> dict:
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def markdown_sections(text: str) -> dict[str, str]:
    """'## Heading' -> body text up to the next '## ' heading."""
    sections, current, buf = {}, None, []
    for line in text.splitlines():
        match = re.match(r"^##\s+(.+?)\s*$", line)
        if match:
            if current is not None:
                sections[current] = "\n".join(buf).strip()
            current, buf = match.group(1), []
        elif current is not None:
            buf.append(line)
    if current is not None:
        sections[current] = "\n".join(buf).strip()
    return sections


def check_doc(path: Path, headings: list[str], template: Path | None = None) -> list[str]:
    """Every heading present with real content: not empty, no TODO, not the template's own text."""
    if not path.exists():
        return [f"missing {path.name}"]
    sections = markdown_sections(path.read_text(encoding="utf-8"))
    template_sections = markdown_sections(template.read_text(encoding="utf-8")) if template else {}
    errors = []
    for heading in headings:
        body = sections.get(heading)
        if body is None:
            errors.append(f"{path.name}: missing section '## {heading}'")
        elif not body or PLACEHOLDER.search(body) or body == template_sections.get(heading):
            errors.append(f"{path.name}: section '{heading}' is empty or still a placeholder")
    return errors


def load_attack_index(bundle_path: Path) -> dict[str, dict]:
    """technique id -> {'tactics': set, 'retired': bool} from a STIX bundle."""
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    index = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        external_id = _mitre_id(obj)
        if not external_id:
            continue
        index[external_id] = {
            "tactics": {p["phase_name"] for p in obj.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"},
            "retired": bool(obj.get("revoked") or obj.get("x_mitre_deprecated")),
        }
    return index


def attack_bundle_version(bundle_path: Path) -> str | None:
    """ATT&CK release number from the bundle's x-mitre-collection object, e.g. "18.0"."""
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version")
    return None


def _mitre_id(stix_object: dict) -> str | None:
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def check_attack(rule: Rule, attack_index: dict[str, dict]) -> list[str]:
    attack = rule.data["mapping"].get("attack")
    if not attack:
        return []
    errors, allowed_tactics = [], set()
    for tid in attack["techniques"]:
        entry = attack_index.get(tid)
        if entry is None:
            errors.append(f"ATT&CK: {tid} not found in the bundle")
        elif entry["retired"]:
            errors.append(f"ATT&CK: {tid} is revoked or deprecated")
        else:
            allowed_tactics |= entry["tactics"]
    for tactic in attack["tactics"]:
        if allowed_tactics and tactic not in allowed_tactics:
            errors.append(f"ATT&CK: tactic {tactic} is not a tactic of {attack['techniques']}")
    return errors


def load_atlas_index(path: Path) -> dict[str, bool]:
    """ATLAS technique id -> deprecated?, from an atlas-data v6 YAML file (`techniques` keyed by id)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {tid: bool(t.get("deprecated")) for tid, t in (data.get("techniques") or {}).items()}


def check_atlas(rule: Rule, atlas_index: dict[str, bool]) -> list[str]:
    errors = []
    for tid in rule.data["mapping"].get("atlas", []):
        if tid not in atlas_index:
            errors.append(f"ATLAS: {tid} not found in the ATLAS data")
        elif atlas_index[tid]:
            errors.append(f"ATLAS: {tid} is deprecated")
    return errors


def check_required_fields(siem: str, required: dict[str, list[str]], allowed: list[str]) -> list[str]:
    errors = []
    for name, fields in required.items():
        if name not in allowed:
            errors.append(f"required_fields names {name!r}, which is not declared for this rule's log sources")
            continue
        reference = load_reference_schema(siem, name)
        if reference is None:
            continue
        known = set(reference.get("fields", []))
        unknown = [f for f in fields if f not in known]
        if unknown:
            errors.append(f"required_fields for {name}: {unknown} not in the reference schema "
                          f"(schemas/reference/{siem}/)")
    return errors


def validate_rule(rule: Rule, schema: dict, catalogue: dict,
                  attack_index: dict | None = None, inventory: dict | None = None,
                  atlas_index: dict | None = None) -> list[str]:
    schema_errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(rule.data),
                           key=lambda e: list(e.path))
    if schema_errors:
        # Later checks assume a schema-valid rule.
        return [f"schema: {'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in schema_errors]

    errors = []
    for source_id in rule.log_sources:
        if source_id not in catalogue:
            errors.append(f"log source {source_id} is not in log_sources.yaml")
    if errors:
        return errors

    for siem in rule.targets():
        allowed = []
        for source_id in rule.log_sources:
            names = catalogue[source_id].get("siem", {}).get(siem)
            if names is None:
                errors.append(f"{siem}: log source {source_id} is not declared for {siem}")
            else:
                allowed.extend(names)
        if allowed:
            adapter = get_adapter(siem, env={})
            errors += [f"{siem}: {e}" for e in adapter.check_query(rule.data[siem], allowed, rule_id=rule.id)]
            errors += [f"{siem}: {e}" for e in check_required_fields(siem, rule.required_fields(siem), allowed)]

    errors += check_doc(rule.folder / "README.md", RULE_DOC_HEADINGS, TEMPLATES_DIR / "rule-doc.md")
    errors += check_doc(rule.folder / "attack.md", ATTACK_DOC_HEADINGS, TEMPLATES_DIR / "attack-doc.md")
    for name in REQUIRED_TEST_FILES:
        if not (rule.folder / "tests" / name).exists():
            errors.append(f"missing tests/{name}")
    if attack_index is not None:
        errors += check_attack(rule, attack_index)
    if atlas_index is not None:
        errors += check_atlas(rule, atlas_index)
    errors += validate_rule_telemetry(rule, inventory if inventory is not None else load_inventory())
    return errors


def validate_all(rules: list[Rule], catalogue: dict, attack_index: dict | None = None,
                 atlas_index: dict | None = None) -> dict[str, list[str]]:
    """Folder name -> errors, only for folders with errors."""
    schema = load_schema()
    inventory = load_inventory()
    results = {}
    id_counts = Counter(rule.data.get("id") for rule in rules)
    for rule in rules:
        errors = validate_rule(rule, schema, catalogue, attack_index, inventory, atlas_index)
        if id_counts[rule.data.get("id")] > 1:
            errors.append(f"duplicate rule id {rule.data.get('id')}")
        if errors:
            results[str(rule.folder)] = errors
    return results


def validate_customers(customers: list[Customer], rules: list[Rule], catalogue: dict) -> dict[str, list[str]]:
    """Customer id -> errors, only for customers with errors."""
    rule_ids = {rule.id for rule in rules}
    inventory = load_inventory()
    results = {}
    for customer in customers:
        errors = []
        if not customer.siems:
            errors.append("customer.yaml lists no siems")
        errors += [f"unknown siem {s!r}" for s in customer.siems if s not in SIEMS]
        for key in ("include", "exclude"):
            errors += [f"{key} names unknown rule id {rid}" for rid in customer.data.get(key, []) if rid not in rule_ids]
        owners = {catalogue[src]["owner"] for rule in customer.applicable_rules(rules)
                  for src in rule.log_sources if src in catalogue}
        errors += [f"teams.yaml has no entry for owning team {team}" for team in sorted(owners - set(customer.teams))]
        errors += validate_apps(customer, inventory)
        if errors:
            results[customer.id] = errors
    return results
