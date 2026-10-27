"""Loading rules and the two catalogues (log sources, teams) from the repo.

A rule lives in its own folder under detections/<track>/<folder>/ with
rule.yaml, README.md (rule doc), attack.md (attack doc) and tests/.
"""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"
LOG_SOURCES_FILE = REPO_ROOT / "log_sources.yaml"
TEAMS_FILE = REPO_ROOT / "teams.yaml"

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
    def log_sources(self) -> list[str]:
        return self.data["log_sources"]

    def targets(self) -> list[str]:
        """SIEMs this rule has a query block for."""
        return [siem for siem in SIEMS if siem in self.data]


def load_yaml(path: Path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_rule(folder: Path) -> Rule:
    return Rule(folder=folder, data=load_yaml(folder / "rule.yaml"))


def find_rule_folders(root: Path = DETECTIONS_DIR) -> list[Path]:
    return sorted(p.parent for p in root.rglob("rule.yaml"))


def load_rules(root: Path = DETECTIONS_DIR) -> list[Rule]:
    return [load_rule(folder) for folder in find_rule_folders(root)]


def load_log_sources(path: Path = LOG_SOURCES_FILE) -> dict:
    return load_yaml(path)


def load_teams(path: Path = TEAMS_FILE) -> dict:
    return load_yaml(path)
