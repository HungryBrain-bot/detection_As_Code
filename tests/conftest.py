import copy
import json
import shutil
from pathlib import Path

import pytest
import yaml

from dac.adapters.base import Response
from dac.rules import Rule, load_log_sources, load_rule, load_teams

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_RULES = FIXTURES / "rules"
FIXTURE_RULE = FIXTURE_RULES / "endpoint" / "fixture-encoded-powershell"


def api_fixture(name: str) -> dict:
    """Response bodies written from each vendor's API reference, not recorded from a live API."""
    return json.loads((FIXTURES / "api" / name).read_text())


class FakeTransport:
    """Records requests and replies from a queue of (status, body) pairs."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        status, body = self.replies.pop(0)
        return Response(status, body)


@pytest.fixture
def catalogue():
    return load_log_sources()


@pytest.fixture
def teams():
    return load_teams()


@pytest.fixture
def rule():
    return load_rule(FIXTURE_RULE)


@pytest.fixture
def rule_copy(tmp_path):
    """A writable copy of the fixture rule folder. Returns (folder, edit) where edit(fn) rewrites rule.yaml."""
    folder = tmp_path / "rules" / "endpoint" / "copy"
    shutil.copytree(FIXTURE_RULE, folder)

    def edit(fn):
        path = folder / "rule.yaml"
        data = yaml.safe_load(path.read_text())
        fn(data)
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        return load_rule(folder)

    return folder, edit


def make_rule(rule: Rule, **changes) -> Rule:
    data = copy.deepcopy(rule.data)
    data.update(changes)
    return Rule(folder=rule.folder, data=data)
