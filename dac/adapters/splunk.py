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
"""

import re

from .base import DeployError, Request, Response, SiemAdapter, check_balanced

# alert.severity: 1 debug, 2 info, 3 low, 4 medium, 5 high, 6 critical
SEVERITY = {"Informational": 2, "Low": 3, "Medium": 4, "High": 5}


def saved_search_name(rule_id: str) -> str:
    return f"dac_{rule_id}"


class SplunkAdapter(SiemAdapter):
    name = "splunk"
    credential_env_vars = ("SPLUNK_URL", "SPLUNK_TOKEN")

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
