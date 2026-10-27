"""Schema check: comparing a rule's required fields with what a probe or the customer reports."""

import yaml

from conftest import FakeTransport, api_fixture
from dac.adapters import ObservedSchema, get_adapter
from dac.rules import schema_file_name
from dac.schema_check import (MISSING_FIELDS, MISSING_TABLE, NO_RECENT_DATA, NOT_CHECKED, OK, check_rule,
                              compare)

REQUIRED = ["EventID", "CommandLine"]


def observed(**kw):
    base = dict(name="SecurityEvent", basis="probe", exists=True, fields={"EventID", "CommandLine"},
                recent_events=10)
    base.update(kw)
    return ObservedSchema(**base)


def test_compare_statuses():
    assert compare("sentinel", "SecurityEvent", REQUIRED, None).status == NOT_CHECKED
    assert compare("sentinel", "SecurityEvent", REQUIRED, observed()).status == OK
    assert compare("sentinel", "SecurityEvent", REQUIRED, observed(exists=False)).status == MISSING_TABLE
    assert compare("sentinel", "SecurityEvent", REQUIRED, observed(recent_events=0)).status == NO_RECENT_DATA
    check = compare("sentinel", "SecurityEvent", REQUIRED, observed(fields={"EventID"}))
    assert check.status == MISSING_FIELDS and check.missing_fields == ["CommandLine"]
    # A customer schema has no event counts; fields alone decide.
    assert compare("sentinel", "SecurityEvent", REQUIRED,
                   observed(basis="customer-schema", recent_events=None)).status == OK


def test_customer_schema_file_is_used_without_probe(rule, customer):
    path = customer.schemas_dir / "splunk" / schema_file_name("XmlWinEventLog:Security")
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump({"name": "XmlWinEventLog:Security", "fields": ["EventCode", "host"],
                                    "provided_by": "Acme SOC", "provided_on": "2026-10-27"}))
    (check,) = check_rule(rule, "splunk", customer, adapter=get_adapter("splunk", env={}))
    assert check.basis == "customer-schema" and check.status == MISSING_FIELDS
    assert "Process_Command_Line" in check.missing_fields


def test_probe_wins_over_customer_schema_and_is_cached(rule, customer):
    env = {"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "s",
           "SENTINEL_WORKSPACE_ID": "w"}
    transport = FakeTransport([(200, api_fixture("sentinel_token.json")),
                               (200, api_fixture("sentinel_getschema.json")),
                               (200, api_fixture("sentinel_count.json"))])
    adapter = get_adapter("sentinel", transport=transport, env=env)
    cache = {}
    (first,) = check_rule(rule, "sentinel", customer, adapter, cache)
    (second,) = check_rule(rule, "sentinel", customer, adapter, cache)
    assert first.basis == "probe" and first.status == OK and second.status == OK
    assert len(transport.requests) == 3   # one probe, reused


def test_missing_reference_schema_does_not_block(rule, customer):
    (check,) = check_rule(rule, "secops", customer, adapter=None)
    assert check.status == NOT_CHECKED and "not checked" in check.describe()
