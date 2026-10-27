"""CLI end to end on the fixture rules and customer, with build/ and reports/ redirected to tmp_path."""

import datetime as dt
import json
import shutil

import pytest

from conftest import FIXTURE_CUSTOMERS, FIXTURE_RULES
from dac import cli
from dac.gate import logsource

ENV_VARS = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "SENTINEL_SUBSCRIPTION_ID",
            "SENTINEL_RESOURCE_GROUP", "SENTINEL_WORKSPACE", "SENTINEL_WORKSPACE_ID",
            "SPLUNK_URL", "SPLUNK_TOKEN", "SECOPS_PROJECT", "SECOPS_REGION", "SECOPS_INSTANCE",
            "SECOPS_ACCESS_TOKEN", "GITHUB_STEP_SUMMARY", "SMTP_HOST"]


class FixedDate(dt.date):
    @classmethod
    def today(cls):
        return dt.date(2026, 10, 27)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "BUILD_DIR", tmp_path / "build")
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(logsource, "NOTIFICATIONS_DIR", tmp_path / "notifications")
    # Pin "today" so fixed confirmation dates never age past the maximum.
    monkeypatch.setattr(logsource.dt, "date", FixedDate)
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    shutil.copytree(FIXTURE_CUSTOMERS, tmp_path / "customers")
    return tmp_path


def run(tmp_path, *args):
    return cli.main(["--rules-dir", str(FIXTURE_RULES), "--customers-dir", str(tmp_path / "customers"), *args])


def confirm(tmp_path, siem="sentinel"):
    path = tmp_path / "customers" / "acme" / "confirmations" / siem / "windows-process-creation.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"log_source: windows-process-creation\nsiem: {siem}\n"
                    "confirmed_by: test\nconfirmed_on: 2026-10-26\nevidence: test\n")


def test_validate_ok(isolated):
    assert run(isolated, "validate") == 0


def test_customers_json(isolated, capsys):
    assert run(isolated, "customers", "--json") == 0
    pairs = json.loads(capsys.readouterr().out)
    assert {"customer": "acme", "siem": "secops"} in pairs and len(pairs) == 3


def test_unknown_customer(isolated):
    assert run(isolated, "gate", "--customer", "nobody", "--siem", "sentinel") == 4


def test_gate_blocks_then_report_only(isolated):
    assert run(isolated, "gate", "--customer", "acme", "--siem", "sentinel") == 2
    assert (isolated / "notifications" / "acme" / "sentinel-endpoint-team.md").exists()
    assert run(isolated, "gate", "--customer", "acme", "--siem", "sentinel", "--report-only") == 0


def test_schema_check_without_probe_or_schema(isolated, capsys):
    assert run(isolated, "schema-check", "--customer", "acme", "--siem", "sentinel") == 2
    out = capsys.readouterr().out
    assert "customer schema files only" in out and "not checked" in out
    assert (isolated / "reports" / "schema" / "acme" / "sentinel.md").exists()


def test_deploy_dry_run_blocked_writes_nothing(isolated):
    assert run(isolated, "deploy", "--customer", "acme", "--siem", "sentinel") == 2
    assert not list((isolated / "build").glob("**/*.json"))


def test_deploy_dry_run_after_confirmation(isolated):
    confirm(isolated)
    assert run(isolated, "deploy", "--customer", "acme", "--siem", "sentinel") == 0
    planned = json.loads(next((isolated / "build" / "acme" / "sentinel").glob("*.json")).read_text())
    assert planned["method"] == "PUT"
    assert "Authorization" not in planned["headers"]


def test_live_without_credentials_exits_3(isolated):
    assert run(isolated, "deploy", "--customer", "acme", "--siem", "sentinel", "--mode", "live") == 3


def test_auto_without_credentials_falls_back_to_dry_run(isolated, capsys):
    assert run(isolated, "deploy", "--customer", "acme", "--siem", "sentinel", "--mode", "auto") == 2
    assert "dry-run only" in capsys.readouterr().out


def test_plan_ignores_gate(isolated):
    assert run(isolated, "plan", "--siem", "secops") == 0
    assert list((isolated / "build" / "all" / "secops").glob("*.json"))


def test_coverage_writes_layer_and_summary(isolated):
    confirm(isolated, "splunk")
    assert run(isolated, "coverage", "--customer", "acme") == 0
    out = isolated / "reports" / "coverage" / "acme"
    layer = json.loads((out / "attack-layer.json").read_text())
    assert layer["techniques"][0]["techniqueID"] == "T1059.001"
    assert layer["techniques"][0]["score"] == 2          # active via Splunk
    assert "active on splunk" in (out / "summary.md").read_text()
    assert not (out / "atlas-layer.json").exists()       # no ATLAS-mapped rules
