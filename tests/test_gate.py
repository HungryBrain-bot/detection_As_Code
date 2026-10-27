"""Log-source gate: confirmations, blocking, and notifier selection."""

import datetime as dt

import pytest
import yaml

from conftest import make_rule
from dac.gate import Notice, SmtpNotifier, run_gate, select_notifier
from dac.gate.notifier import FileNotifier

TODAY = dt.date(2026, 10, 27)
SOURCE = "windows-process-creation"


def confirm(conf_dir, folder_siem="sentinel", source=SOURCE, **overrides):
    """Write confirmations/<siem>/<source>.yaml; overrides change fields inside the file only."""
    data = {"log_source": source, "siem": folder_siem, "confirmed_by": "Endpoint Engineering (test)",
            "confirmed_on": TODAY - dt.timedelta(days=1), "evidence": "test"}
    data.update(overrides)
    path = conf_dir / folder_siem / f"{source}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data))


@pytest.fixture
def dirs(tmp_path):
    return tmp_path / "confirmations", tmp_path / "notifications"


def gate(rules, dirs, catalogue, teams, siem="sentinel", env=None, **kw):
    conf_dir, notif_dir = dirs
    return run_gate(rules, siem, catalogue, teams, today=TODAY, confirmations_dir=conf_dir,
                    notifications_dir=notif_dir, env=env or {}, **kw)


def test_blocks_without_confirmation_and_writes_reminder(rule, dirs, catalogue, teams):
    result = gate([rule], dirs, catalogue, teams)
    assert not result.passed
    assert rule.id in result.blocked
    assert "no confirmation for sentinel" in result.blocked[rule.id][0]
    notice = (dirs[1] / "sentinel-endpoint-team.md").read_text()
    assert SOURCE in notice and rule.name in notice and "SecurityEvent" in notice
    assert "no email on file" in notice


def test_allows_with_current_confirmation(rule, dirs, catalogue, teams):
    confirm(dirs[0])
    result = gate([rule], dirs, catalogue, teams)
    assert result.passed and result.allowed == [rule.id]
    assert result.deliveries == []


def test_confirmation_is_per_siem(rule, dirs, catalogue, teams):
    confirm(dirs[0], folder_siem="sentinel")
    assert not gate([rule], dirs, catalogue, teams, siem="splunk").passed


@pytest.mark.parametrize("overrides, expected", [
    ({"confirmed_on": TODAY - dt.timedelta(days=91)}, "days old"),
    ({"confirmed_on": TODAY + dt.timedelta(days=1)}, "in the future"),
    ({"confirmed_on": "last week"}, "YYYY-MM-DD"),
    ({"confirmed_by": ""}, "no confirmed_by"),
    ({"siem": "splunk"}, "does not match"),
])
def test_bad_confirmations_block(rule, dirs, catalogue, teams, overrides, expected):
    confirm(dirs[0], **overrides)
    result = gate([rule], dirs, catalogue, teams)
    assert expected in result.blocked[rule.id][0]


def test_rule_not_targeting_siem_is_ignored(rule, dirs, catalogue, teams):
    sentinel_only = make_rule(rule)
    del sentinel_only.data["splunk"]
    result = gate([sentinel_only], dirs, catalogue, teams, siem="splunk")
    assert result.passed and result.allowed == [] and result.deliveries == []


def test_one_reminder_per_team(rule, dirs, catalogue, teams):
    second = make_rule(rule, id="bb6e3de5-1813-4234-8137-df07958a0359", name="Second rule")
    result = gate([rule, second], dirs, catalogue, teams)
    assert len(result.deliveries) == 1
    notice = (dirs[1] / "sentinel-endpoint-team.md").read_text()
    assert "Second rule" in notice and rule.name in notice


def test_no_notify_mode(rule, dirs, catalogue, teams):
    result = gate([rule], dirs, catalogue, teams, notify=False)
    assert result.blocked and not dirs[1].exists()


def test_reminder_goes_to_job_summary(rule, dirs, catalogue, teams, tmp_path):
    summary = tmp_path / "summary.md"
    gate([rule], dirs, catalogue, teams, env={"GITHUB_STEP_SUMMARY": str(summary)})
    assert "Confirm 1 log source(s) in sentinel" in summary.read_text()


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


def test_gate_mails_team_with_address(rule, dirs, catalogue, teams):
    teams = {**teams, "endpoint-team": {"name": "Endpoint Engineering", "email": "endpoint@example.com"}}
    result = gate([rule], dirs, catalogue, teams, env=SMTP_ENV, smtp_factory=FakeSMTP)
    assert result.deliveries == ["endpoint-team: email to endpoint@example.com"]
    assert not dirs[1].exists()
