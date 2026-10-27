"""Loading rules, customers and the log-source catalogue from the repo.

A rule lives in its own folder under detections/<track>/<folder>/ with
rule.yaml, README.md (rule doc), attack.md (attack doc) and tests/.

A customer lives in customers/<id>/ (ADR 004):

    customer.yaml     name, the SIEMs they run, targeted rules to include,
                      baseline rules to exclude
    teams.yaml        the customer's owning teams and contacts
    confirmations/    <siem>/<log_source>.yaml, the gate's human confirmations
    schemas/          <siem>/<table>.yaml, schemas the customer sent us
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"
CUSTOMERS_DIR = REPO_ROOT / "customers"
LOG_SOURCES_FILE = REPO_ROOT / "log_sources.yaml"
REFERENCE_SCHEMAS_DIR = REPO_ROOT / "schemas" / "reference"

SIEMS = ("sentinel", "splunk", "secops")


@dataclass
class Rule:
    folder: Path
    data: dict = field(repr=False)

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def name(self) -> str:
        return self.data["name"]

    @property
    def version(self) -> int:
        return self.data["version"]

    @property
    def tier(self) -> str:
        return self.data.get("tier", "targeted")

    @property
    def log_sources(self) -> list[str]:
        return self.data["log_sources"]

    def targets(self) -> list[str]:
        """SIEMs this rule has a query block for."""
        return [siem for siem in SIEMS if siem in self.data]

    def required_fields(self, siem: str) -> dict[str, list[str]]:
        """Table / source / log type -> fields the query for this SIEM uses."""
        return self.data.get(siem, {}).get("required_fields", {})


@dataclass
class Customer:
    folder: Path
    data: dict = field(repr=False)
    teams: dict = field(repr=False, default_factory=dict)

    @property
    def id(self) -> str:
        return self.folder.name

    @property
    def name(self) -> str:
        return self.data.get("name", self.id)

    @property
    def siems(self) -> list[str]:
        return self.data.get("siems", [])

    @property
    def confirmations_dir(self) -> Path:
        return self.folder / "confirmations"

    @property
    def schemas_dir(self) -> Path:
        return self.folder / "schemas"

    def applicable_rules(self, rules: list[Rule]) -> list[Rule]:
        """Baseline rules unless excluded, plus targeted rules the customer includes."""
        include = set(self.data.get("include", []))
        exclude = set(self.data.get("exclude", []))
        return [rule for rule in rules
                if (rule.tier == "baseline" and rule.id not in exclude) or rule.id in include]


def load_yaml(path: Path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_rule(folder: Path) -> Rule:
    return Rule(folder=folder, data=load_yaml(folder / "rule.yaml"))


def find_rule_folders(root: Path = DETECTIONS_DIR) -> list[Path]:
    return sorted(p.parent for p in root.rglob("rule.yaml"))


def load_rules(root: Path = DETECTIONS_DIR) -> list[Rule]:
    return [load_rule(folder) for folder in find_rule_folders(root)]


def load_customer(folder: Path) -> Customer:
    teams_file = folder / "teams.yaml"
    teams = load_yaml(teams_file) if teams_file.exists() else {}
    return Customer(folder=folder, data=load_yaml(folder / "customer.yaml"), teams=teams)


def load_customers(root: Path = CUSTOMERS_DIR) -> list[Customer]:
    return [load_customer(p.parent) for p in sorted(root.glob("*/customer.yaml"))]


def load_log_sources(path: Path = LOG_SOURCES_FILE) -> dict:
    return load_yaml(path)


def schema_file_name(name: str) -> str:
    """Splunk sources contain ':' and '/', so file names use a safe form of the name."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) + ".yaml"


def load_reference_schema(siem: str, name: str, root: Path = REFERENCE_SCHEMAS_DIR) -> dict | None:
    """Vendor-documented schema for a table / source / log type, if one is in the repo."""
    path = root / siem / schema_file_name(name)
    return load_yaml(path) if path.exists() else None
