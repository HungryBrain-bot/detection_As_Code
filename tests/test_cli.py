"""CLI end to end on the fixture rules, with build/ and reports/ redirected to tmp_path."""

import json

import pytest

from conftest import FIXTURE_RULES
from dac import cli
from dac.gate import logsource

SENTINEL_ENV_VARS = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
                     "SENTINEL_SUBSCRIPTION_ID", "SENTINEL_RESOURCE_GROUP", "SENTINEL_WORKSPACE"]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "BUILD_DIR", tmp_path / "build")
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(logsource, "CONFIRMATIONS_DIR", tmp_path / "confirmations")
    monkeypatch.setattr(logsource, "NOTIFICATIONS_DIR", tmp_path / "notifications")
    for var in SENTINEL_ENV_VARS + ["GITHUB_STEP_SUMMARY", "SMTP_HOST"]:
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def run(*args):
    return cli.main(["--rules-dir", str(FIXTURE_RULES), *args])


def confirm(tmp_path):
    path = tmp_path / "confirmations" / "sentinel" / "windows-process-creation.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("log_source: windows-process-creation\nsiem: sentinel\n"
                    "confirmed_by: test\nconfirmed_on: 2026-10-26\nevidence: test\n")


def test_validate_ok():
    assert run("validate") == 0


def test_gate_blocks_then_report_only(isolated):
    assert run("gate", "--siem", "sentinel") == 2
    assert (isolated / "notifications" / "sentinel-endpoint-team.md").exists()
    assert run("gate", "--siem", "sentinel", "--report-only") == 0


def test_deploy_dry_run_blocked_writes_nothing(isolated):
    assert run("deploy", "--siem", "sentinel") == 2
    assert not list((isolated / "build").glob("**/*.json"))


def test_deploy_dry_run_after_confirmation(isolated, monkeypatch):
    # Pin "today" so the fixed confirmation date is never older than the max age.
    import datetime as dt

    class FixedDate(dt.date):
        @classmethod
        def today(cls):
            return dt.date(2026, 10, 27)

    monkeypatch.setattr(logsource.dt, "date", FixedDate)
    confirm(isolated)
    assert run("deploy", "--siem", "sentinel") == 0
    planned = json.loads(next((isolated / "build" / "sentinel").glob("*.json")).read_text())
    assert planned["method"] == "PUT"
    assert "Authorization" not in planned["headers"]


def test_live_without_credentials_exits_3():
    assert run("deploy", "--siem", "sentinel", "--mode", "live") == 3


def test_auto_without_credentials_falls_back_to_dry_run(capsys):
    assert run("deploy", "--siem", "sentinel", "--mode", "auto") == 2  # still gated
    assert "dry-run only" in capsys.readouterr().out


def test_plan_ignores_gate(isolated):
    assert run("plan", "--siem", "secops") == 0
    assert list((isolated / "build" / "secops").glob("*.json"))
