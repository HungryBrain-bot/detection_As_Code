"""Coverage: only gate-passed rules count; layers and summary say what is active and blocked."""

import datetime as dt
import json

from conftest import make_rule
from dac.coverage import ACTIVE, BLOCKED, navigator_layer, rule_statuses, summary_markdown, write_coverage
from dac.gate import GateResult

TODAY = dt.date(2026, 10, 27)


def results(customer, rule, allowed_on=(), blocked_on=()):
    out = []
    for siem in customer.siems:
        r = GateResult(customer=customer.id, siem=siem)
        if siem in allowed_on:
            r.allowed.append(rule.id)
        elif siem in blocked_on:
            r.blocked[rule.id] = ["windows-process-creation: no confirmation for " + siem]
        out.append(r)
    return out


def test_active_if_allowed_on_any_siem(rule, customer):
    (status,) = rule_statuses(customer, [rule], results(customer, rule, allowed_on=["splunk"],
                                                        blocked_on=["sentinel", "secops"]))
    assert status.status == ACTIVE and status.active_on == ["splunk"]


def test_blocked_rule_is_not_coverage(rule, customer):
    statuses = rule_statuses(customer, [rule], results(customer, rule, blocked_on=customer.siems))
    assert statuses[0].status == BLOCKED
    layer = navigator_layer(customer, statuses, "enterprise-attack", "attack", TODAY)
    assert layer["techniques"][0]["score"] == 1
    summary = summary_markdown(customer, statuses, TODAY)
    assert "**0 of 1 applicable rules are active**" in summary
    assert "no confirmation for sentinel" in summary


def test_rules_not_applicable_to_customer_are_left_out(rule, customer):
    targeted = make_rule(rule, tier="targeted")
    assert rule_statuses(customer, [targeted], []) == []


def test_atlas_layer_for_llm_rules(rule, customer, tmp_path):
    llm = make_rule(rule, mapping={"owasp_llm_2025": ["LLM01"], "atlas": ["AML.T0051"]})
    written = write_coverage(customer, [llm], results(customer, llm, allowed_on=["sentinel"]),
                             out_dir=tmp_path, today=TODAY)
    names = {p.name for p in written}
    assert names == {"atlas-layer.json", "summary.md"}
    layer = json.loads((tmp_path / customer.id / "atlas-layer.json").read_text())
    assert layer["techniques"][0] == {"techniqueID": "AML.T0051", "score": 2, "color": "#31a354",
                                      "comment": layer["techniques"][0]["comment"], "enabled": True}


def test_attack_version_from_bundle_goes_in_layer(rule, customer):
    statuses = rule_statuses(customer, [rule], results(customer, rule, allowed_on=["sentinel"]))
    layer = navigator_layer(customer, statuses, "enterprise-attack", "attack", TODAY, attack_version="20.0")
    assert layer["versions"]["attack"] == "20.0" and layer["techniques"][0]["tactic"] == "execution"
