"""Log-source gate: per customer, human confirmations, probe auto-confirmation, reminders, notifiers."""

import datetime as dt

import pytest
import yaml

from conftest import FakeTransport, api_fixture, make_rule
from dac.adapters import get_adapter
from dac.gate import Notice, SmtpNotifier, run_gate, select_notifier
from dac.gate.notifier import FileNotifier
from dac.rules import load_customer

TODAY = dt.date(2026, 10, 27)
SOURCE = "windows-process-creation"
PROBE_ENV = {"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "s",
             "SENTINEL_WORKSPACE_ID": "00000000-0000-0000-0000-000000000000"}


def confirm(customer, folder_siem="sentinel", source=SOURCE, **overrides):
    """Write customers/<id>/confirmations/<siem>/<source>.yaml; overrides change fields inside the file only."""
    data = {"log_source": source, "siem": folder_siem, "confirmed_by": "Endpoint Engineering (test)",
            "confirmed_on": TODAY - dt.timedelta(days=1), "evidence": "test"}
    data.update(overrides)
    path = customer.confirmations_dir / folder_siem / f"{source}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data))


def customer_schema(customer, siem, name, fields):
    from dac.rules import schema_file_name
    path = customer.schemas_dir / siem / schema_file_name(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"name": name, "fields": fields, "provided_by": "test",
                                    "provided_on": TODAY}))


@pytest.fixture
def notif_dir(tmp_path):
    return tmp_path / "notifications"


def gate(rules, customer, catalogue, notif_dir, siem="sentinel", env=None, **kw):
    return run_gate(rules, siem, catalogue, customer, today=TODAY,
                    notifications_dir=notif_dir, env=env or {}, **kw)


def reminder(notif_dir, customer, siem="sentinel", team="endpoint-team"):
    return (notif_dir / customer.id / f"{siem}-{team}.md").read_text()


# --- human confirmations ---------------------------------------------------

def test_blocks_without_confirmation_and_writes_reminder(rule, customer, catalogue, notif_dir):
    result = gate([rule], customer, catalogue, notif_dir)
    assert not result.passed
    assert "no confirmation for sentinel" in result.blocked[rule.id][0]
    notice = reminder(notif_dir, customer)
    assert SOURCE in notice and rule.name in notice and "SecurityEvent" in notice
    assert "CommandLine" in notice                       # the fields the rule reads
    assert "Syslog or CommonSecurityLog" in notice       # SIEM-specific "lands elsewhere" ask
    assert f"customers/{customer.id}/schemas/sentinel/" in notice
    assert "no email on file" in notice


def test_allows_with_current_confirmation(rule, customer, catalogue, notif_dir):
    confirm(customer)
    result = gate([rule], customer, catalogue, notif_dir)
    assert result.passed and result.allowed == [rule.id]
    assert result.deliveries == [] and result.auto_confirmed == {}


def test_confirmation_is_per_siem(rule, customer, catalogue, notif_dir):
    confirm(customer, folder_siem="sentinel")
    assert not gate([rule], customer, catalogue, notif_dir, siem="splunk").passed


def test_splunk_reminder_talks_about_indexes(rule, customer, catalogue, notif_dir):
    gate([rule], customer, catalogue, notif_dir, siem="splunk")
    notice = reminder(notif_dir, customer, siem="splunk")
    assert "index, source or sourcetype" in notice and "Syslog" not in notice


@pytest.mark.parametrize("overrides, expected", [
    ({"confirmed_on": TODAY - dt.timedelta(days=91)}, "days old"),
    ({"confirmed_on": TODAY + dt.timedelta(days=1)}, "in the future"),
    ({"confirmed_on": "last week"}, "YYYY-MM-DD"),
    ({"confirmed_by": ""}, "no confirmed_by"),
    ({"siem": "splunk"}, "does not match"),
])
def test_bad_confirmations_block(rule, customer, catalogue, notif_dir, overrides, expected):
    confirm(customer, **overrides)
    result = gate([rule], customer, catalogue, notif_dir)
    assert expected in result.blocked[rule.id][0]


def test_customer_schema_missing_fields_blocks_even_with_confirmation(rule, customer, catalogue, notif_dir):
    confirm(customer)
    customer_schema(customer, "sentinel", "SecurityEvent", ["TimeGenerated", "EventID", "Computer"])
    result = gate([rule], customer, catalogue, notif_dir)
    assert any("missing fields" in r and "CommandLine" in r for r in result.blocked[rule.id])


def test_customer_schema_complete_still_needs_confirmation(rule, customer, catalogue, notif_dir):
    customer_schema(customer, "sentinel", "SecurityEvent", rule.required_fields("sentinel")["SecurityEvent"])
    result = gate([rule], customer, catalogue, notif_dir)
    assert result.blocked[rule.id] == [f"{SOURCE}: no confirmation for sentinel"]


# --- probe -----------------------------------------------------------------

def sentinel_probe(replies):
    token = (200, api_fixture("sentinel_token.json"))
    return get_adapter("sentinel", transport=FakeTransport([token, *replies]), env=PROBE_ENV)


def test_probe_pass_auto_confirms_without_human(rule, customer, catalogue, notif_dir):
    adapter = sentinel_probe([(200, api_fixture("sentinel_getschema.json")),
                              (200, api_fixture("sentinel_count.json"))])
    result = gate([rule], customer, catalogue, notif_dir, adapter=adapter)
    assert result.allowed == [rule.id]
    assert result.auto_confirmed == {rule.id: [SOURCE]}
    assert result.deliveries == []


def test_probe_gap_blocks_even_with_human_confirmation(rule, customer, catalogue, notif_dir):
    confirm(customer)
    adapter = sentinel_probe([(400, api_fixture("sentinel_table_missing.json"))])
    result = gate([rule], customer, catalogue, notif_dir, adapter=adapter)
    assert "not found in sentinel (probe)" in result.blocked[rule.id][0]
    assert "not found in sentinel" in reminder(notif_dir, customer)


def test_probe_no_recent_data_blocks(rule, customer, catalogue, notif_dir):
    empty = {"tables": [{"rows": [[0]]}]}
    adapter = sentinel_probe([(200, api_fixture("sentinel_getschema.json")), (200, empty)])
    result = gate([rule], customer, catalogue, notif_dir, adapter=adapter)
    assert "no events in the last 24h" in result.blocked[rule.id][0]


def test_failed_probe_falls_back_to_confirmation(rule, customer, catalogue, notif_dir):
    confirm(customer)
    adapter = get_adapter("sentinel", transport=FakeTransport([(401, {})]), env=PROBE_ENV)
    result = gate([rule], customer, catalogue, notif_dir, adapter=adapter)
    assert result.allowed == [rule.id]
    assert result.checks[rule.id][0].basis == "probe failed"


# --- customers, tiers ------------------------------------------------------

def test_siem_the_customer_does_not_run_is_skipped(rule, customer, catalogue, notif_dir):
    customer.data["siems"] = ["sentinel"]
    result = gate([rule], customer, catalogue, notif_dir, siem="splunk")
    assert result.allowed == [] and result.blocked == {}


def test_targeted_rule_only_for_customers_that_include_it(rule, customer, catalogue, notif_dir):
    targeted = make_rule(rule, tier="targeted")
    assert gate([targeted], customer, catalogue, notif_dir).blocked == {}
    customer.data["include"] = [rule.id]
    assert rule.id in gate([targeted], customer, catalogue, notif_dir).blocked


def test_excluded_baseline_rule_is_skipped(rule, customer, catalogue, notif_dir):
    customer.data["exclude"] = [rule.id]
    assert gate([rule], customer, catalogue, notif_dir).blocked == {}


def test_one_reminder_per_team(rule, customer, catalogue, notif_dir):
    second = make_rule(rule, id="bb6e3de5-1813-4234-8137-df07958a0359", name="Second rule")
    result = gate([rule, second], customer, catalogue, notif_dir)
    assert len(result.deliveries) == 1
    notice = reminder(notif_dir, customer)
    assert "Second rule" in notice and rule.name in notice


def test_no_notify_mode(rule, customer, catalogue, notif_dir):
    result = gate([rule], customer, catalogue, notif_dir, notify=False)
    assert result.blocked and not notif_dir.exists()


def test_reminder_goes_to_job_summary(rule, customer, catalogue, notif_dir, tmp_path):
    summary = tmp_path / "summary.md"
    gate([rule], customer, catalogue, notif_dir, env={"GITHUB_STEP_SUMMARY": str(summary)})
    assert "check 1 log source(s) in sentinel" in summary.read_text()


def test_repo_demo_customer_loads():
    from dac.rules import CUSTOMERS_DIR
    demo = load_customer(CUSTOMERS_DIR / "demo")
    assert demo.siems == ["sentinel"] and "endpoint-team" in demo.teams


# --- notifier selection ----------------------------------------------------

class FakeSMTP:
    sent = []

    def __init__(self, host, port, timeout):
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        pass

    def login(self, user, password):
        pass

    def send_message(self, message):
        FakeSMTP.sent.append(message)


NOTICE = Notice("endpoint-team", "Endpoint Engineering", "", "sentinel", "subject", "body")
SMTP_ENV = {"SMTP_HOST": "smtp.example", "SMTP_FROM": "dac@example.com"}


def test_file_notifier_when_no_email(tmp_path):
    assert isinstance(select_notifier(NOTICE, tmp_path, env=SMTP_ENV), FileNotifier)


def test_file_notifier_when_smtp_not_configured(tmp_path):
    with_email = Notice(**{**NOTICE.__dict__, "email": "team@example.com"})
    assert isinstance(select_notifier(with_email, tmp_path, env={}), FileNotifier)


def test_smtp_when_email_and_smtp_configured(tmp_path):
    with_email = Notice(**{**NOTICE.__dict__, "email": "team@example.com"})
    notifier = select_notifier(with_email, tmp_path, env=SMTP_ENV, smtp_factory=FakeSMTP)
    assert isinstance(notifier, SmtpNotifier)
    assert notifier.send(with_email) == "email to team@example.com"
    message = FakeSMTP.sent[-1]
    assert message["To"] == "team@example.com" and message["From"] == "dac@example.com"


def test_gate_mails_team_with_address(rule, customer, catalogue, notif_dir):
    customer.teams["endpoint-team"] = {"name": "Endpoint Engineering", "email": "endpoint@example.com"}
    result = gate([rule], customer, catalogue, notif_dir, env=SMTP_ENV, smtp_factory=FakeSMTP)
    assert result.deliveries == ["endpoint-team: email to endpoint@example.com"]
    assert not notif_dir.exists()
