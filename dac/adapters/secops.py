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
"""

import re

from .base import Request, Response, SiemAdapter, check_balanced, DeployError


def secops_rule_name(rule_id: str) -> str:
    return "dac_" + rule_id.replace("-", "_")


class SecOpsAdapter(SiemAdapter):
    name = "secops"
    credential_env_vars = ("SECOPS_PROJECT", "SECOPS_REGION", "SECOPS_INSTANCE", "SECOPS_ACCESS_TOKEN")

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
