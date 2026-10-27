"""Splunk adapter (SPL scheduled saved searches with an alert condition).

Deploy: POST to the saved/searches REST endpoint. The saved search is
named ``dac_<rule uuid>`` so renaming a rule never creates a duplicate;
the human-readable name goes in the description. If the search already
exists (HTTP 409) the adapter retries as an update to
saved/searches/<name>. Auth is a Splunk authentication token sent as a
Bearer header.

What check_query checks (offline, not an SPL parser):
- brackets and double quotes balance;
- the search is scoped with ``index=`` (an unscoped search scans every
  default index, which is slow and depends on the user's role);
- the search mentions at least one source/sourcetype declared for its
  log sources in log_sources.yaml.

Not checked: SPL syntax, field names, that the index exists. Not
verified against a live Splunk: the endpoint and field names are from
Splunk's REST API reference, not from a call.

Schema probe (read-only): one export search over the last 24h,
``search index=* (source="<name>" OR sourcetype="<name>") | fieldsummary``,
which returns each field seen and its event count. Splunk has no table
catalogue to ask, so "no results" cannot be told apart from "this
sourcetype does not exist": both report exists=None, 0 events. The
token's role needs search access to the indexes holding the data and
nothing else. ``index=*`` scans every index the role can read: an
accepted cost for a probe run per deploy over at most 10 rules; scope
it to known indexes if probes ever run often. Not verified against a
live Splunk: the export response format (one JSON object per line) is
from Splunk's REST reference.
"""

import json
import re

from .base import DeployError, ObservedSchema, ProbeError, Request, Response, SiemAdapter, check_balanced

# alert.severity: 1 debug, 2 info, 3 low, 4 medium, 5 high, 6 critical
SEVERITY = {"Informational": 2, "Low": 3, "Medium": 4, "High": 5}


def saved_search_name(rule_id: str) -> str:
    return f"dac_{rule_id}"


class SplunkAdapter(SiemAdapter):
    name = "splunk"
    credential_env_vars = ("SPLUNK_URL", "SPLUNK_TOKEN")
    probe_env_vars = ("SPLUNK_URL", "SPLUNK_TOKEN")

    def check_query(self, rule_block: dict, allowed_sources: list[str], rule_id: str | None = None) -> list[str]:
        search = rule_block["search"]
        errors = check_balanced(search)
        if not re.search(r"\bindex\s*=", search):
            errors.append("search has no index= scope")
        if not any(name in search for name in allowed_sources):
            errors.append(f"search does not reference any declared source/sourcetype: {allowed_sources}")
        return errors

    def _base(self) -> str:
        app = self.env.get("SPLUNK_APP") or "search"
        return f"{self._env('SPLUNK_URL').rstrip('/')}/servicesNS/nobody/{app}/saved/searches"

    def _fields(self, rule) -> dict:
        block = rule.data["splunk"]
        return {
            "description": f"{rule.name}. {rule.data['description'].strip()}",
            "search": block["search"].strip(),
            "cron_schedule": block["cron_schedule"],
            "is_scheduled": "1",
            "dispatch.earliest_time": block["earliest_time"],
            "dispatch.latest_time": block.get("latest_time", "now"),
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.severity": str(SEVERITY[rule.data["severity"]]),
            "alert.track": "1",
            # Experimental rules are created disabled, as in Sentinel.
            "disabled": "0" if rule.data["status"] in ("test", "stable") else "1",
        }

    def build_request(self, rule) -> Request:
        body = {"name": saved_search_name(rule.id), **self._fields(rule)}
        return Request("POST", f"{self._base()}?output_mode=json", body=body, form_encoded=True)

    def build_update_request(self, rule) -> Request:
        url = f"{self._base()}/{saved_search_name(rule.id)}?output_mode=json"
        return Request("POST", url, body=self._fields(rule), form_encoded=True)

    def auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.env['SPLUNK_TOKEN']}"}

    def deploy(self, rule) -> Response:
        try:
            return super().deploy(rule)
        except DeployError as exc:
            if "HTTP 409" not in str(exc):
                raise
        update = self.build_update_request(rule)
        update.headers.update(self.auth_headers())
        response = self.transport.send(update)
        if response.status >= 300:
            raise DeployError(f"splunk: update {update.url} -> HTTP {response.status}: {response.body}")
        return response

    def probe(self, name: str) -> ObservedSchema:
        if '"' in name or "\\" in name:
            raise ProbeError(f"splunk: refusing to probe unusual source name {name!r}")
        search = (f'search index=* (source="{name}" OR sourcetype="{name}") '
                  "| fieldsummary | fields field count")
        request = Request("POST", f"{self._env('SPLUNK_URL').rstrip('/')}/services/search/jobs/export",
                          headers=self.auth_headers(),
                          body={"search": search, "output_mode": "json",
                                "earliest_time": "-24h", "latest_time": "now"},
                          form_encoded=True)
        response = self.transport.send(request)
        if response.status != 200:
            raise ProbeError(f"splunk: probe search for {name} -> HTTP {response.status}")
        counts = {}
        for line in _export_lines(response.body):
            result = line.get("result") or {}
            if "field" in result:
                counts[result["field"]] = int(result.get("count") or 0)
        if not counts:
            return ObservedSchema(name, "probe", exists=None, fields=None, recent_events=0,
                                  note="no events in 24h (Splunk cannot tell a missing source from an empty one)")
        recent = counts.get("_time", max(counts.values()))
        return ObservedSchema(name, "probe", exists=True, fields=set(counts), recent_events=recent)


def _export_lines(body: dict) -> list[dict]:
    """The export endpoint returns one JSON object per line, which Transport keeps as body['raw']."""
    if "raw" not in body:
        return [body]
    lines = []
    for line in body["raw"].splitlines():
        line = line.strip()
        if line:
            try:
                lines.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return lines
