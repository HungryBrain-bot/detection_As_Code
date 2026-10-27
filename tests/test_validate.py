"""Validator: schema, log-source declarations, query checks, docs and ATT&CK mapping."""

import json

from dac.rules import DETECTIONS_DIR, load_rules
from dac.validate import check_attack, load_attack_index, load_schema, validate_all, validate_rule


def errors_for(rule, catalogue, attack_index=None):
    return validate_rule(rule, load_schema(), catalogue, attack_index)


def test_fixture_rule_passes(rule, catalogue):
    assert errors_for(rule, catalogue) == []


def test_repo_rules_pass(catalogue):
    """Every real rule under detections/ must pass. Zero rules is a pass."""
    assert validate_all(load_rules(DETECTIONS_DIR), catalogue) == {}


def test_schema_errors_stop_further_checks(rule_copy, catalogue):
    _, edit = rule_copy
    broken = edit(lambda d: d.pop("severity"))
    errors = errors_for(broken, catalogue)
    assert len(errors) == 1 and "severity" in errors[0]


def test_rule_needs_a_siem_block(rule_copy, catalogue):
    _, edit = rule_copy

    def strip(d):
        for siem in ("sentinel", "splunk", "secops"):
            d.pop(siem)

    assert any("schema" in e for e in errors_for(edit(strip), catalogue))


def test_unknown_log_source(rule_copy, catalogue):
    _, edit = rule_copy
    errors = errors_for(edit(lambda d: d.update(log_sources=["not-a-source"])), catalogue)
    assert errors == ["log source not-a-source is not in log_sources.yaml"]


def test_log_source_not_declared_for_siem(rule_copy, catalogue):
    _, edit = rule_copy
    # entra-audit exists only in Sentinel, but the fixture also targets Splunk and SecOps.
    errors = errors_for(edit(lambda d: d.update(log_sources=["entra-audit"])), catalogue)
    assert "splunk: log source entra-audit is not declared for splunk" in errors
    assert "secops: log source entra-audit is not declared for secops" in errors
    assert any(e.startswith("sentinel: query does not reference") for e in errors)


def test_placeholder_doc_section_fails(rule_copy, catalogue):
    folder, edit = rule_copy
    doc = folder / "README.md"
    doc.write_text(doc.read_text().replace("Fixture text: none.\n", "TODO\n", 1))
    errors = errors_for(edit(lambda d: None), catalogue)
    assert any("still a placeholder" in e for e in errors)


def test_templates_have_the_validated_headings():
    from dac.validate import ATTACK_DOC_HEADINGS, RULE_DOC_HEADINGS, TEMPLATES_DIR, markdown_sections
    assert list(markdown_sections((TEMPLATES_DIR / "rule-doc.md").read_text())) == RULE_DOC_HEADINGS
    assert list(markdown_sections((TEMPLATES_DIR / "attack-doc.md").read_text())) == ATTACK_DOC_HEADINGS


def test_unedited_template_fails(rule_copy, catalogue):
    from dac.validate import TEMPLATES_DIR
    folder, edit = rule_copy
    (folder / "attack.md").write_text((TEMPLATES_DIR / "attack-doc.md").read_text())
    errors = errors_for(edit(lambda d: None), catalogue)
    assert sum("attack.md" in e and "placeholder" in e for e in errors) == 7


def test_missing_doc_and_tests(rule_copy, catalogue):
    folder, edit = rule_copy
    (folder / "attack.md").unlink()
    (folder / "tests" / "evidence.md").unlink()
    errors = errors_for(edit(lambda d: None), catalogue)
    assert "missing attack.md" in errors and "missing tests/evidence.md" in errors


def test_duplicate_ids(rule, catalogue):
    results = validate_all([rule, rule], catalogue)
    assert any("duplicate rule id" in e for e in results[str(rule.folder)])


# --- ATT&CK mapping against a STIX bundle ----------------------------------

def stix_technique(tid, tactics, **extra):
    return {"type": "attack-pattern",
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics],
            **extra}


def write_bundle(tmp_path, objects):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"type": "bundle", "objects": objects}))
    return load_attack_index(path)


def test_attack_mapping_passes(rule, tmp_path):
    index = write_bundle(tmp_path, [stix_technique("T1059.001", ["execution"])])
    assert check_attack(rule, index) == []


def test_attack_unknown_retired_and_wrong_tactic(rule_copy, tmp_path):
    _, edit = rule_copy
    index = write_bundle(tmp_path, [
        stix_technique("T1059.001", ["execution"]),
        stix_technique("T1086", ["execution"], revoked=True),
    ])
    wrong_tactic = edit(lambda d: d["mapping"]["attack"].update(tactics=["persistence"]))
    assert "tactic persistence" in check_attack(wrong_tactic, index)[0]
    retired = edit(lambda d: d["mapping"]["attack"].update(techniques=["T1086"], tactics=["execution"]))
    assert "revoked or deprecated" in check_attack(retired, index)[0]
    unknown = edit(lambda d: d["mapping"]["attack"].update(techniques=["T9999"]))
    assert "not found" in check_attack(unknown, index)[0]
