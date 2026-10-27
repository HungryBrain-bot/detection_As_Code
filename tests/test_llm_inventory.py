"""LLM log-source inventory (dac/llm_inventory.py): structure checks, rule telemetry, feed report."""

import copy

import pytest
import yaml

from dac import cli
from dac.llm_inventory import (check_feed, load_inventory, report, validate_apps, validate_inventory,
                               validate_rule_telemetry)
from dac.rules import REPO_ROOT, Rule, load_customer, load_log_sources, load_rules
from dac.validate import check_atlas

from conftest import make_rule


@pytest.fixture
def inventory():
    return load_inventory()


def llm_rule(rule, populated=("OperationName", "InputText"), extra_tables=None):
    required = {"LLMAppLog_CL": ["TimeGenerated", "OperationName", "InputText", "OutputText"]}
    required.update(extra_tables or {})
    data = copy.deepcopy(rule.data)
    data["sentinel"]["required_fields"] = required
    data["llm_telemetry"] = {"populated": list(populated)}
    return Rule(folder=rule.folder, data=data)


def test_repo_inventory_is_valid(inventory, catalogue):
    assert validate_inventory(inventory, catalogue) == []


def test_every_repo_llm_rule_declares_its_telemetry(inventory):
    llm = [r for r in load_rules() if "LLMAppLog_CL" in r.required_fields("sentinel")]
    assert {r.folder.name[:2] for r in llm} >= {"C1", "C2", "C3"}
    assert all(validate_rule_telemetry(r, inventory) == [] for r in llm)


def test_inventory_rejects_unknown_column_and_missing_siem(inventory, catalogue):
    broken = copy.deepcopy(inventory)
    source = broken["sources"]["otel-genai"]
    source["maps_to"]["PromptText"] = "gen_ai.prompt"
    del source["integration"]["secops"]
    errors = validate_inventory(broken, catalogue)
    assert any("PromptText" in e for e in errors)
    assert any("integration must say something" in e for e in errors)


def test_inventory_rejects_missing_keys_and_unknown_log_source(inventory, catalogue):
    broken = copy.deepcopy(inventory)
    del broken["sources"]["mcp-server"]["gaps"]
    broken["sources"]["otel-genai"]["log_source"] = "llm-nope"
    broken["sources"]["otel-genai"]["status"] = "great"
    errors = validate_inventory(broken, catalogue)
    assert any("mcp-server: missing ['gaps']" in e for e in errors)
    assert any("llm-nope" in e for e in errors)
    assert any("status must be" in e for e in errors)


def test_rule_reading_llm_table_needs_llm_telemetry(rule, inventory):
    llm = llm_rule(rule)
    del llm.data["llm_telemetry"]
    assert "no llm_telemetry.populated" in validate_rule_telemetry(llm, inventory)[0]
    wrong = llm_rule(rule, populated=["ToolName"])
    assert "not in required_fields" in validate_rule_telemetry(wrong, inventory)[0]
    assert validate_rule_telemetry(rule, inventory) == []   # endpoint rule: not concerned


def test_feed_needs_content_capture_for_text_columns(rule, inventory, catalogue):
    llm = llm_rule(rule)
    app = {"sources": ["otel-genai"], "content_capture": False}
    assert check_feed("a", app, llm, inventory, catalogue).missing == ["InputText (content capture is off)"]
    assert check_feed("a", dict(app, content_capture=True), llm, inventory, catalogue).ok


def test_feed_reports_columns_no_source_fills_and_app_added_columns(rule, inventory, catalogue):
    llm = llm_rule(rule, populated=["OperationName", "ConversationId", "UserId"])
    gateway = {"sources": ["azure-apim-ai-gateway"], "content_capture": True}
    missing = check_feed("a", gateway, llm, inventory, catalogue).missing
    assert missing == ["ConversationId (no source fills it)", "UserId (no source fills it)"]
    otel = {"sources": ["otel-genai"], "content_capture": True, "adds_columns": ["UserId"]}
    assert check_feed("a", otel, llm, inventory, catalogue).ok


def test_feed_needs_a_source_for_each_other_table(rule, inventory, catalogue):
    llm = llm_rule(rule, extra_tables={"LLMCanary_CL": ["CanaryValue"]})
    app = {"sources": ["otel-genai"], "content_capture": True}
    assert check_feed("a", app, llm, inventory, catalogue).missing == [
        "table LLMCanary_CL (no source of this app writes it)"]
    app["sources"].append("llm-canary-registry")
    assert check_feed("a", app, llm, inventory, catalogue).ok


def test_apps_file_checks(customer, inventory):
    (customer.folder / "llm_apps.yaml").write_text(yaml.safe_dump({"apps": {"bot": {
        "owner": "nobody", "sources": ["otel-genai", "made-up"], "content_capture": "yes",
        "adds_columns": ["Nope"]}}}))
    errors = validate_apps(load_customer(customer.folder), inventory)
    assert len(errors) == 4
    assert any("owner 'nobody'" in e for e in errors) and any("made-up" in e for e in errors)


def test_demo_report_shows_which_app_can_feed_which_rule(inventory):
    demo = load_customer(REPO_ROOT / "customers" / "demo")
    assert validate_apps(demo, inventory) == []
    text, gaps = report(demo, load_rules(), inventory, load_log_sources())
    support = text.split("## support-agent")[1].split("## marketing-copy")[0]
    marketing = text.split("## marketing-copy")[1]
    assert "| no |" not in support
    assert "| yes |" not in marketing and "content capture is off" in marketing
    assert gaps == 3


def test_cli_llm_inventory_writes_report_and_exits_2_on_gaps(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path)
    assert cli.main(["llm-inventory", "--customer", "demo"]) == 2
    assert "## support-agent" in (tmp_path / "llm" / "demo.md").read_text()


def test_atlas_ids_are_checked(rule):
    llm = make_rule(rule, mapping={"atlas": ["AML.T0051.000", "AML.T9999", "AML.T0001"]})
    index = {"AML.T0051.000": False, "AML.T0001": True}
    assert check_atlas(llm, index) == ["ATLAS: AML.T9999 not found in the ATLAS data",
                                       "ATLAS: AML.T0001 is deprecated"]
