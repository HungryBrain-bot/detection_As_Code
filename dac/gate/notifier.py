"""Pluggable delivery for log-source reminders.

Two notifiers, one interface:

- ``SmtpNotifier`` mails the team, when SMTP_HOST and SMTP_FROM are set
  and the team has an email in teams.yaml.
- ``FileNotifier`` writes the reminder to reports/notifications/ and, in
  GitHub Actions, appends it to the job summary. It is the fallback,
  so a reminder is never silently dropped.

``select_notifier`` picks per team, so one team with an address gets
mail while the others still get a file. See
docs/components/log-source-gate.md.
"""

import os
import smtplib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path


@dataclass
class Notice:
    team_id: str
    team_name: str
    email: str
    siem: str
    subject: str
    body: str


class Notifier(ABC):
    channel: str

    @abstractmethod
    def send(self, notice: Notice) -> str:
        """Deliver the notice; return a short description of where it went."""


class FileNotifier(Notifier):
    channel = "file"

    def __init__(self, out_dir: Path, env: dict | None = None):
        self.out_dir = out_dir
        self.env = os.environ if env is None else env

    def send(self, notice: Notice) -> str:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / f"{notice.siem}-{notice.team_id}.md"
        text = f"# {notice.subject}\n\nTo: {notice.team_name} ({notice.email or 'no email on file'})\n\n{notice.body}\n"
        path.write_text(text, encoding="utf-8")
        summary = self.env.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(text + "\n")
        return str(path)


class SmtpNotifier(Notifier):
    channel = "email"

    def __init__(self, env: dict | None = None, smtp_factory=smtplib.SMTP):
        self.env = os.environ if env is None else env
        self.smtp_factory = smtp_factory

    @staticmethod
    def configured(env) -> bool:
        return bool(env.get("SMTP_HOST") and env.get("SMTP_FROM"))

    def send(self, notice: Notice) -> str:
        message = EmailMessage()
        message["From"] = self.env["SMTP_FROM"]
        message["To"] = notice.email
        message["Subject"] = notice.subject
        message.set_content(notice.body)
        port = int(self.env.get("SMTP_PORT") or 587)
        with self.smtp_factory(self.env["SMTP_HOST"], port, timeout=30) as smtp:
            smtp.starttls()
            if self.env.get("SMTP_USER"):
                smtp.login(self.env["SMTP_USER"], self.env.get("SMTP_PASSWORD", ""))
            smtp.send_message(message)
        return f"email to {notice.email}"


def select_notifier(notice: Notice, out_dir: Path, env: dict | None = None, smtp_factory=smtplib.SMTP) -> Notifier:
    env = os.environ if env is None else env
    if notice.email and SmtpNotifier.configured(env):
        return SmtpNotifier(env=env, smtp_factory=smtp_factory)
    return FileNotifier(out_dir, env=env)
