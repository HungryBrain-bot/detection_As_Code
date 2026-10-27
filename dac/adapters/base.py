"""The one interface every SIEM adapter implements.

An adapter does three things for one rule:

- ``check_query``: offline structural checks on the rule's query for
  this SIEM's language. These are not a real parser; see each
  adapter's docstring for exactly what it checks.
- ``build_request``: the exact HTTP request a deploy would send. Pure,
  no network, no credentials needed except for URL parts, which fall
  back to placeholders in dry-run.
- ``deploy``: send that request. Only runs when every credential env
  var for the adapter is set; otherwise raises MissingCredentials.

Dry-run is the default everywhere. See docs/decisions/002-adapter-interface.md.
"""

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class MissingCredentials(RuntimeError):
    pass


class ProbeError(RuntimeError):
    pass


class DeployError(RuntimeError):
    pass


@dataclass
class Request:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: dict | None = None
    # Splunk's REST API takes form-encoded bodies, the others take JSON.
    form_encoded: bool = False

    def redacted(self) -> dict:
        """Printable form for dry-run output: auth headers are never shown."""
        headers = {k: ("<redacted>" if k.lower() == "authorization" else v)
                   for k, v in self.headers.items()}
        return {"method": self.method, "url": self.url,
                "headers": headers, "body": self.body}


@dataclass
class Response:
    status: int
    body: dict


@dataclass
class ObservedSchema:
    """What a SIEM (or a customer-sent schema file) says about one table / source / log type."""
    name: str
    basis: str                   # "probe" (queried live) or "customer-schema" (a file the customer sent)
    exists: bool | None          # None: this SIEM cannot tell "missing" from "no events"
    fields: set[str] | None      # None: not known
    recent_events: int | None    # events in the last 24h; None: not known
    note: str = ""


class Transport:
    """Minimal stdlib HTTP client. Tests swap in a fake with the same send()."""

    def send(self, request: Request) -> Response:
        if request.form_encoded:
            from urllib.parse import urlencode
            data = urlencode(request.body or {}).encode()
            content_type = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(request.body).encode() if request.body is not None else None
            content_type = "application/json"
        req = urllib.request.Request(request.url, data=data, method=request.method,
                                     headers={**request.headers, "Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode() or "{}"
                return Response(resp.status, _parse(raw))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, _parse(exc.read().decode() or "{}"))


def _parse(raw: str) -> dict:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}
    return parsed if isinstance(parsed, dict) else {"data": parsed}


def check_balanced(text: str, pairs: str = "()[]{}") -> list[str]:
    """Bracket and double-quote balance. Shared by all three query languages.

    Ignores brackets inside double-quoted strings. Does not understand
    escapes beyond a backslash before a quote, single-quoted strings or
    verbatim strings, so it can be fooled; it catches truncated queries.
    """
    openers = {pairs[i]: pairs[i + 1] for i in range(0, len(pairs), 2)}
    closers = set(openers.values())
    stack = []
    in_string = False
    prev = ""
    for ch in text:
        if ch == '"' and prev != "\\":
            in_string = not in_string
        elif not in_string:
            if ch in openers:
                stack.append(openers[ch])
            elif ch in closers:
                if not stack or stack.pop() != ch:
                    return [f"unbalanced '{ch}'"]
        prev = ch
    errors = []
    if in_string:
        errors.append("unterminated double-quoted string")
    if stack:
        errors.append(f"unclosed bracket, expected '{stack[-1]}'")
    return errors


class SiemAdapter(ABC):
    #: key in rule.yaml and log_sources.yaml
    name: str
    #: env vars that must all be set before deploy() will run
    credential_env_vars: tuple[str, ...]
    #: env vars that must all be set before probe() will run (read-only access)
    probe_env_vars: tuple[str, ...] = ()

    def __init__(self, transport: Transport | None = None, env: dict | None = None):
        self.transport = transport or Transport()
        self.env = os.environ if env is None else env

    def has_credentials(self) -> bool:
        return all(self.env.get(var) for var in self.credential_env_vars)

    def missing_credentials(self) -> list[str]:
        return [var for var in self.credential_env_vars if not self.env.get(var)]

    def has_probe_credentials(self) -> bool:
        return bool(self.probe_env_vars) and all(self.env.get(var) for var in self.probe_env_vars)

    def probe(self, name: str) -> ObservedSchema:
        """Ask the live SIEM which fields `name` has and how many events arrived in 24h.

        Read-only. Only called when has_probe_credentials() is true.
        """
        raise NotImplementedError(f"{self.name} has no schema probe")

    def _env(self, var: str) -> str:
        """Credential/config value, or a visible placeholder for dry-run URLs."""
        return self.env.get(var) or f"<{var}>"

    @abstractmethod
    def check_query(self, rule_block: dict, allowed_sources: list[str], rule_id: str | None = None) -> list[str]:
        """Return a list of problems with the query; empty means it passed."""

    @abstractmethod
    def build_request(self, rule) -> Request:
        """The deploy request for this rule, without auth headers."""

    @abstractmethod
    def auth_headers(self) -> dict:
        """Auth headers for a live call. Only called when credentials are set."""

    def deploy(self, rule) -> Response:
        if not self.has_credentials():
            raise MissingCredentials(
                f"{self.name}: not deploying, missing env vars: {', '.join(self.missing_credentials())}")
        request = self.build_request(rule)
        request.headers.update(self.auth_headers())
        response = self.transport.send(request)
        if response.status >= 300:
            raise DeployError(f"{self.name}: {request.method} {request.url} -> "
                              f"HTTP {response.status}: {response.body}")
        return response
