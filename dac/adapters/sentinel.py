"""Microsoft Sentinel adapter (KQL scheduled analytics rules).

Deploy: one idempotent PUT per rule to the Security Insights alertRules
endpoint, keyed on the rule's UUID, so re-running a deploy updates the
rule rather than creating a duplicate. Auth is an Entra ID app
(client-credentials flow) with the Microsoft Sentinel Contributor role
on the workspace.

What check_query checks (offline, not a KQL parser):
- brackets and double quotes balance;
- the query references at least one table name declared for its log
  sources in log_sources.yaml (as a whole word);
- query_period >= query_frequency, and both within 5 minutes to 14 days.

What it does not check: KQL syntax, that columns exist, that the
query returns rows, or anything about the real workspace. Not verified
against a live workspace: the API version and the exact property set
below were taken from Microsoft's REST reference, not from a call.
"""

import re

from .base import Request, SiemAdapter, check_balanced

API_VERSION = "2023-11-01"  # Security Insights GA version; not verified by a live call.
MIN_MINUTES = 5
MAX_MINUTES = 14 * 24 * 60

_DURATION = re.compile(r"^P(?:(\d+)D|T(\d+)([HM]))$")


def iso_minutes(value: str) -> int:
    """PT5M / PT1H / P1D -> minutes. Only the shapes rule.schema.json allows."""
    match = _DURATION.match(value)
    if not match:
        raise ValueError(f"unsupported duration {value!r}")
    days, amount, unit = match.groups()
    if days:
        return int(days) * 24 * 60
    return int(amount) * (60 if unit == "H" else 1)


def sentinel_tactic(attack_shortname: str) -> str:
    """ATT&CK shortname (credential-access) -> Sentinel enum (CredentialAccess)."""
    return "".join(part.capitalize() for part in attack_shortname.split("-"))


def parent_techniques(technique_ids: list[str]) -> list[str]:
    """Sentinel's `techniques` field takes parent IDs (T1059, not T1059.001)."""
    parents = []
    for tid in technique_ids:
        parent = tid.split(".")[0]
        if parent not in parents:
            parents.append(parent)
    return parents


def references_any(query: str, names: list[str]) -> bool:
    return any(re.search(rf"(?<![\w.]){re.escape(name)}(?![\w])", query) for name in names)


class SentinelAdapter(SiemAdapter):
    name = "sentinel"
    credential_env_vars = (
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "SENTINEL_SUBSCRIPTION_ID", "SENTINEL_RESOURCE_GROUP", "SENTINEL_WORKSPACE",
    )

    def check_query(self, rule_block: dict, allowed_sources: list[str], rule_id: str | None = None) -> list[str]:
        query = rule_block["query"]
        errors = check_balanced(query)
        if not references_any(query, allowed_sources):
            errors.append(f"query does not reference any declared table: {allowed_sources}")
        try:
            frequency = iso_minutes(rule_block["query_frequency"])
            period = iso_minutes(rule_block["query_period"])
        except ValueError as exc:
            return errors + [str(exc)]
        for label, minutes in (("query_frequency", frequency), ("query_period", period)):
            if not MIN_MINUTES <= minutes <= MAX_MINUTES:
                errors.append(f"{label} must be between 5 minutes and 14 days")
        if period < frequency:
            errors.append("query_period is shorter than query_frequency, so events would be missed")
        return errors

    def rule_url(self, rule_id: str) -> str:
        return (
            "https://management.azure.com"
            f"/subscriptions/{self._env('SENTINEL_SUBSCRIPTION_ID')}"
            f"/resourceGroups/{self._env('SENTINEL_RESOURCE_GROUP')}"
            "/providers/Microsoft.OperationalInsights/workspaces/"
            f"{self._env('SENTINEL_WORKSPACE')}"
            f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
            f"?api-version={API_VERSION}"
        )

    def build_request(self, rule) -> Request:
        block = rule.data["sentinel"]
        attack = rule.data["mapping"].get("attack", {})
        properties = {
            "displayName": rule.name,
            "description": rule.data["description"].strip(),
            "severity": rule.data["severity"],
            # Experimental rules are deployed disabled: they exist in the
            # workspace for review but raise no incidents.
            "enabled": rule.data["status"] in ("test", "stable"),
            "query": block["query"].strip(),
            "queryFrequency": block["query_frequency"],
            "queryPeriod": block["query_period"],
            "triggerOperator": "GreaterThan",
            "triggerThreshold": block.get("trigger_threshold", 0),
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": [sentinel_tactic(t) for t in attack.get("tactics", [])],
            "techniques": parent_techniques(attack.get("techniques", [])),
        }
        return Request("PUT", self.rule_url(rule.id),
                       body={"kind": "Scheduled", "properties": properties})

    def auth_headers(self) -> dict:
        token_request = Request(
            "POST",
            f"https://login.microsoftonline.com/{self.env['AZURE_TENANT_ID']}/oauth2/v2.0/token",
            body={
                "grant_type": "client_credentials",
                "client_id": self.env["AZURE_CLIENT_ID"],
                "client_secret": self.env["AZURE_CLIENT_SECRET"],
                "scope": "https://management.azure.com/.default",
            },
            form_encoded=True,
        )
        response = self.transport.send(token_request)
        token = response.body.get("access_token")
        if response.status != 200 or not token:
            # Never echo the response body: it can contain request details.
            raise RuntimeError(f"sentinel: token request failed with HTTP {response.status}")
        return {"Authorization": f"Bearer {token}"}
