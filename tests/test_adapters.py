"""Adapters: offline query checks, request building, and deploy against a fake transport.

The fake transport replies with bodies from tests/fixtures/api/, which
were written from vendor docs, not recorded. These tests prove the
requests we build and how we handle documented responses; they do not
prove a live API accepts them.
"""

import pytest

from conftest import FakeTransport, api_fixture, make_rule
from dac.adapters import DeployError, MissingCredentials, get_adapter
from dac.adapters.base import check_balanced
from dac.adapters.secops import secops_rule_name
from dac.adapters.sentinel import iso_minutes, parent_techniques, sentinel_tactic

SENTINEL_ENV = {
    "AZURE_TENANT_ID": "tenant", "AZURE_CLIENT_ID": "client", "AZURE_CLIENT_SECRET": "secret",
    "SENTINEL_SUBSCRIPTION_ID": "sub", "SENTINEL_RESOURCE_GROUP": "rg", "SENTINEL_WORKSPACE": "ws",
}
SPLUNK_ENV = {"SPLUNK_URL": "https://splunk.example:8089", "SPLUNK_TOKEN": "tok"}
SECOPS_ENV = {"SECOPS_PROJECT": "p", "SECOPS_REGION": "us", "SECOPS_INSTANCE": "i",
              "SECOPS_ACCESS_TOKEN": "tok"}


# --- shared helpers -------------------------------------------------------

@pytest.mark.parametrize("text, ok", [
    ('T | where x in ("a", "b")', True),
    ('T | where x == "(not a bracket"', True),
    ("T | where (x", False),
    ("T | where x)", False),
    ('T | where x == "open', False),
    ("rule r { events: [ } ]", False),
])
def test_check_balanced(text, ok):
    assert (check_balanced(text) == []) is ok


def test_sentinel_helpers():
    assert iso_minutes("PT5M") == 5
    assert iso_minutes("PT2H") == 120
    assert iso_minutes("P1D") == 1440
    assert sentinel_tactic("credential-access") == "CredentialAccess"
    assert parent_techniques(["T1059.001", "T1059.003", "T1105"]) == ["T1059", "T1105"]


# --- Sentinel --------------------------------------------------------------

def test_sentinel_query_checks(rule):
    adapter = get_adapter("sentinel", env={})
    block = rule.data["sentinel"]
    assert adapter.check_query(block, ["SecurityEvent"]) == []
    assert "declared table" in adapter.check_query(block, ["SigninLogs"])[0]
    # A table name that only appears as a prefix of another word does not count.
    assert adapter.check_query({**block, "query": "SecurityEventX | take 1"}, ["SecurityEvent"])
    short = {**block, "query_period": "PT30M"}
    assert any("shorter than" in e for e in adapter.check_query(short, ["SecurityEvent"]))
    too_fast = {**block, "query_frequency": "PT1M", "query_period": "PT1M"}
    assert any("between 5 minutes" in e for e in adapter.check_query(too_fast, ["SecurityEvent"]))


def test_sentinel_request(rule):
    request = get_adapter("sentinel", env=SENTINEL_ENV).build_request(rule)
    assert request.method == "PUT"
    assert request.url.endswith(f"/alertRules/{rule.id}?api-version=2023-11-01")
    assert "/workspaces/ws/" in request.url
    props = request.body["properties"]
    assert request.body["kind"] == "Scheduled"
    assert props["tactics"] == ["Execution"]
    assert props["techniques"] == ["T1059"]
    assert props["enabled"] is False  # experimental -> deployed disabled
    stable = get_adapter("sentinel", env={}).build_request(make_rule(rule, status="stable"))
    assert stable.body["properties"]["enabled"] is True


def test_dry_run_url_uses_placeholders_without_env(rule):
    request = get_adapter("sentinel", env={}).build_request(rule)
    assert "<SENTINEL_WORKSPACE>" in request.url


def test_sentinel_deploy_needs_credentials(rule):
    adapter = get_adapter("sentinel", env={"AZURE_TENANT_ID": "t"})
    with pytest.raises(MissingCredentials) as exc:
        adapter.deploy(rule)
    assert "AZURE_CLIENT_SECRET" in str(exc.value)


def test_sentinel_deploy(rule):
    transport = FakeTransport([(200, api_fixture("sentinel_token.json")),
                               (201, api_fixture("sentinel_alert_rule.json"))])
    get_adapter("sentinel", transport=transport, env=SENTINEL_ENV).deploy(rule)
    token_call, put_call = transport.requests
    assert token_call.url == "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
    assert token_call.form_encoded and token_call.body["scope"] == "https://management.azure.com/.default"
    assert put_call.method == "PUT"
    assert put_call.headers["Authorization"] == "Bearer fake-token-for-tests"
    assert put_call.redacted()["headers"]["Authorization"] == "<redacted>"


def test_sentinel_token_failure_does_not_echo_body(rule):
    transport = FakeTransport([(401, {"error_description": "secret detail"})])
    with pytest.raises(RuntimeError) as exc:
        get_adapter("sentinel", transport=transport, env=SENTINEL_ENV).deploy(rule)
    assert "401" in str(exc.value) and "secret detail" not in str(exc.value)


def test_sentinel_deploy_error(rule):
    transport = FakeTransport([(200, api_fixture("sentinel_token.json")), (400, {"error": "bad"})])
    with pytest.raises(DeployError):
        get_adapter("sentinel", transport=transport, env=SENTINEL_ENV).deploy(rule)


# --- Splunk ----------------------------------------------------------------

def test_splunk_query_checks(rule):
    adapter = get_adapter("splunk", env={})
    block = rule.data["splunk"]
    allowed = ["XmlWinEventLog:Security"]
    assert adapter.check_query(block, allowed) == []
    unscoped = {**block, "search": block["search"].replace("index=wineventlog ", "")}
    assert "index=" in adapter.check_query(unscoped, allowed)[0]
    assert adapter.check_query(block, ["XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"])


def test_splunk_request(rule):
    request = get_adapter("splunk", env=SPLUNK_ENV).build_request(rule)
    assert request.url == "https://splunk.example:8089/servicesNS/nobody/search/saved/searches?output_mode=json"
    assert request.form_encoded
    assert request.body["name"] == f"dac_{rule.id}"
    assert request.body["alert.severity"] == "4"
    assert request.body["disabled"] == "1"


def test_splunk_deploy_creates(rule):
    transport = FakeTransport([(201, api_fixture("splunk_saved_search.json"))])
    get_adapter("splunk", transport=transport, env=SPLUNK_ENV).deploy(rule)
    assert transport.requests[0].headers["Authorization"] == "Bearer tok"


def test_splunk_deploy_updates_on_conflict(rule):
    transport = FakeTransport([(409, api_fixture("splunk_conflict.json")),
                               (200, api_fixture("splunk_saved_search.json"))])
    get_adapter("splunk", transport=transport, env=SPLUNK_ENV).deploy(rule)
    update = transport.requests[1]
    assert update.url.endswith(f"/saved/searches/dac_{rule.id}?output_mode=json")
    assert "name" not in update.body
    assert update.headers["Authorization"] == "Bearer tok"


# --- Google SecOps ---------------------------------------------------------

def test_secops_query_checks(rule):
    adapter = get_adapter("secops", env={})
    block = rule.data["secops"]
    assert adapter.check_query(block, ["WINDOWS_SYSMON"], rule_id=rule.id) == []
    assert adapter.check_query(block, ["POWERSHELL"], rule_id=rule.id)
    renamed = {"rule_text": block["rule_text"].replace(secops_rule_name(rule.id), "my_rule")}
    assert "rule name must be" in adapter.check_query(renamed, ["WINDOWS_SYSMON"], rule_id=rule.id)[0]
    no_condition = {"rule_text": block["rule_text"].replace("condition:", "")}
    assert adapter.check_query(no_condition, ["WINDOWS_SYSMON"], rule_id=rule.id)


def test_secops_deploy_creates_when_absent(rule):
    transport = FakeTransport([(200, api_fixture("secops_rules_empty.json")),
                               (200, api_fixture("secops_rule.json"))])
    get_adapter("secops", transport=transport, env=SECOPS_ENV).deploy(rule)
    listing, create = transport.requests
    assert listing.method == "GET"
    assert create.method == "POST"
    assert create.url == "https://us-chronicle.googleapis.com/v1alpha/projects/p/locations/us/instances/i/rules"
    assert create.body["text"].startswith(f"rule {secops_rule_name(rule.id)} {{")


def test_secops_deploy_patches_when_present(rule):
    transport = FakeTransport([(200, api_fixture("secops_rules_existing.json")),
                               (200, api_fixture("secops_rule.json"))])
    get_adapter("secops", transport=transport, env=SECOPS_ENV).deploy(rule)
    patch = transport.requests[1]
    assert patch.method == "PATCH"
    assert patch.url.endswith("/instances/i/rules/ru_0000-1111?update_mask=text")


def test_secops_deploy_needs_credentials(rule):
    with pytest.raises(MissingCredentials):
        get_adapter("secops", env={}).deploy(rule)


def test_unknown_adapter():
    with pytest.raises(ValueError):
        get_adapter("qradar")
