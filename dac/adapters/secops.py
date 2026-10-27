"""Google SecOps adapter (YARA-L 2.0 detection rules).

YARA-L is Google SecOps' rule language for UDM events. It is not YARA,
which matches byte patterns in files; the two only share a name and
the meta/condition layout.

Deploy: SecOps assigns its own rule IDs, so the rule cannot be keyed on
our UUID directly. Instead the YARA-L rule name must be
``dac_<uuid with underscores>`` (checked offline), and deploy lists the
instance's rules, finds one with that display name, and PATCHes its
text, or POSTs a new rule if none exists. Creating or updating a rule
does not turn on live detection or alerting in SecOps; that is a
separate deployment setting and is deliberately left manual here.

Auth: a short-lived OAuth access token in SECOPS_ACCESS_TOKEN, minted
in CI by a prior step (for example ``gcloud auth print-access-token``
from a service account). The adapter never handles a service-account
key itself.

What check_query checks (offline, not a YARA-L compiler):
- braces, brackets and double quotes balance;
- the rule header is ``rule dac_<uuid> {``;
- meta:, events: and condition: sections exist, in that order;
- the events section filters on a ``metadata.log_type`` declared for
  the rule's log sources in log_sources.yaml.

Not checked: UDM field names, YARA-L semantics, match windows. Not
verified against a live instance: the v1alpha endpoint shape is from
Google's API reference, not from a call.

Schema probe (read-only), the least certain of the three: a UDM search
for ``metadata.log_type = "<LOG_TYPE>"`` over the last 24h, limited to
100 events, and the union of the UDM field paths present in those
events. The endpoint name, parameters and response shape are my
reading of the v1alpha API and are unverified [guess]; check them on
the first live call. A sample of 100 events can miss fields that only
some events carry, so a "missing field" here means "not seen in the
sample". As with Splunk, zero events cannot be told apart from a log
type that is not ingested. The token needs read (viewer) access only.
"""

import datetime as dt
import re
from urllib.parse import urlencode

from .base import DeployError, ObservedSchema, ProbeError, Request, Response, SiemAdapter, check_balanced

PROBE_SAMPLE = 100
_LOG_TYPE = re.compile(r"^[A-Z0-9_]+$")


def secops_rule_name(rule_id: str) -> str:
    return "dac_" + rule_id.replace("-", "_")


class SecOpsAdapter(SiemAdapter):
    name = "secops"
    credential_env_vars = ("SECOPS_PROJECT", "SECOPS_REGION", "SECOPS_INSTANCE", "SECOPS_ACCESS_TOKEN")
    probe_env_vars = credential_env_vars

    def check_query(self, rule_block: dict, allowed_sources: list[str], rule_id: str | None = None) -> list[str]:
        text = rule_block["rule_text"]
        errors = check_balanced(text)
        header = re.search(r"^\s*rule\s+([A-Za-z0-9_]+)\s*\{", text, re.MULTILINE)
        if not header:
            errors.append("missing 'rule <name> {' header")
        elif rule_id and header.group(1) != secops_rule_name(rule_id):
            errors.append(f"rule name must be {secops_rule_name(rule_id)}, got {header.group(1)}")
        positions = [text.find(section) for section in ("meta:", "events:", "condition:")]
        if -1 in positions:
            errors.append("rule needs meta:, events: and condition: sections")
        elif positions != sorted(positions):
            errors.append("sections must appear in the order meta:, events:, condition:")
        log_types = re.findall(r"metadata\.log_type\s*=\s*\"([A-Z0-9_]+)\"", text)
        if not any(lt in allowed_sources for lt in log_types):
            errors.append(f"events must filter metadata.log_type on a declared log type: {allowed_sources}")
        return errors

    def _instance(self) -> str:
        region = self._env("SECOPS_REGION")
        return (f"https://{region}-chronicle.googleapis.com/v1alpha"
                f"/projects/{self._env('SECOPS_PROJECT')}/locations/{region}"
                f"/instances/{self._env('SECOPS_INSTANCE')}")

    def build_request(self, rule) -> Request:
        """The create request. deploy() switches to PATCH when the rule exists."""
        return Request("POST", f"{self._instance()}/rules",
                       body={"text": rule.data["secops"]["rule_text"].strip()})

    def auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.env['SECOPS_ACCESS_TOKEN']}"}

    def _find_existing(self, rule) -> str | None:
        """Resource name of the SecOps rule with our display name, if any.

        Reads only the first page (pageSize=1000): an accepted limit for a
        repo with 10 rules; follow nextPageToken if an instance ever has more.
        """
        listing = Request("GET", f"{self._instance()}/rules?pageSize=1000", headers=self.auth_headers())
        response = self.transport.send(listing)
        if response.status >= 300:
            raise DeployError(f"secops: listing rules -> HTTP {response.status}")
        wanted = secops_rule_name(rule.id)
        for existing in response.body.get("rules", []):
            if existing.get("displayName") == wanted:
                return existing["name"]
        return None

    def deploy(self, rule) -> Response:
        if not self.has_credentials():
            return super().deploy(rule)  # raises MissingCredentials
        existing = self._find_existing(rule)
        request = self.build_request(rule)
        if existing:
            request = Request("PATCH", f"https://{self._env('SECOPS_REGION')}-chronicle.googleapis.com"
                              f"/v1alpha/{existing}?update_mask=text", body=request.body)
        request.headers.update(self.auth_headers())
        response = self.transport.send(request)
        if response.status >= 300:
            raise DeployError(f"secops: {request.method} {request.url} -> HTTP {response.status}: {response.body}")
        return response

    def probe(self, name: str, now: dt.datetime | None = None) -> ObservedSchema:
        if not _LOG_TYPE.match(name):
            raise ProbeError(f"secops: refusing to probe unusual log type {name!r}")
        now = now or dt.datetime.now(dt.timezone.utc)
        params = urlencode({
            "query": f'metadata.log_type = "{name}"',
            "timeRange.startTime": (now - dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "timeRange.endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "limit": PROBE_SAMPLE,
        })
        response = self.transport.send(Request("GET", f"{self._instance()}:udmSearch?{params}",
                                               headers=self.auth_headers()))
        if response.status != 200:
            raise ProbeError(f"secops: UDM search for {name} -> HTTP {response.status}")
        events = response.body.get("events", [])
        if not events:
            return ObservedSchema(name, "probe", exists=None, fields=None, recent_events=0,
                                  note="no events in 24h (cannot tell a missing log type from an empty one)")
        fields = set()
        for event in events:
            fields |= udm_paths(event.get("udm", {}))
        note = f"fields seen in a sample of {len(events)} event(s)"
        return ObservedSchema(name, "probe", exists=True, fields=fields, recent_events=len(events), note=note)


def snake(key: str) -> str:
    """API JSON uses camelCase (commandLine); YARA-L and rule required_fields use snake_case (command_line)."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()


def udm_paths(value, prefix: str = "") -> set[str]:
    """Dotted snake_case UDM paths present in an event: {"target": {"ip": [..]}} -> {"target", "target.ip"}."""
    paths = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{snake(key)}" if prefix else snake(key)
            paths.add(path)
            paths |= udm_paths(child, path)
    elif isinstance(value, list):
        for item in value:
            paths |= udm_paths(item, prefix)
    return paths
