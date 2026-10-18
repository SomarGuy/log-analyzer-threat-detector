import copy
import json

import pytest

from loganalyzer.rules import DEFAULT_RULES_PATH, RuleError, load_rules


def doc():
    return json.loads(DEFAULT_RULES_PATH.read_text())


def write(tmp_path, d):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(d))
    return p


def test_default_rules_load_and_every_rule_has_mitre_and_response(rules):
    assert len(rules) >= 15
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    for r in rules:
        assert r.mitre and r.response and r.description, r.id
        assert all(m["id"].startswith("T") for m in r.mitre)


def test_default_rule_ids_cover_required_attack_families(rule_by_id):
    for rid in ("AUTH-001", "AUTH-002", "AUTH-003", "ACCT-002", "AUTH-004", "WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-006"):
        assert rid in rule_by_id
    techniques = {m["id"] for r in rule_by_id.values() for m in r.mitre}
    assert {"T1110.001", "T1110.003", "T1078", "T1136.001", "T1190", "T1595.002"} <= techniques


def test_missing_file(tmp_path):
    with pytest.raises(RuleError, match="not found"):
        load_rules(tmp_path / "nope.json")


def test_invalid_json(tmp_path):
    p = tmp_path / "r.json"
    p.write_text("{oops")
    with pytest.raises(RuleError, match="not valid JSON"):
        load_rules(p)


def test_empty_rules_list(tmp_path):
    with pytest.raises(RuleError, match="non-empty"):
        load_rules(write(tmp_path, {"rules": []}))


def test_bare_list_is_accepted(tmp_path):
    rules = load_rules(write(tmp_path, doc()["rules"]))
    assert rules


@pytest.mark.parametrize("mutate,message", [
    (lambda r: r.pop("id"), "missing required field 'id'"),
    (lambda r: r.update(type="telepathy"), "unknown rule type"),
    (lambda r: r.update(severity="catastrophic"), "severity must be"),
    (lambda r: r.update(sources=[]), "sources"),
    (lambda r: r.update(sources=["dns"]), "sources"),
    (lambda r: r["params"].pop("threshold"), "missing param 'threshold'"),
    (lambda r: r["params"].update(threshold=0), "positive integer"),
    (lambda r: r["params"].update(window_seconds="5m"), "positive integer"),
    (lambda r: r.update(mitre=[]), "MITRE"),
    (lambda r: r.update(mitre=[{"id": "1110", "name": "x", "tactic": "y"}]), "invalid MITRE"),
    (lambda r: r.update(mitre=[{"id": "T1110", "name": "", "tactic": "y"}]), "needs 'name' and 'tactic'"),
])
def test_validation_errors(tmp_path, mutate, message):
    d = doc()
    rule = next(r for r in d["rules"] if r["id"] == "AUTH-001")
    mutate(rule)
    with pytest.raises(RuleError, match=message):
        load_rules(write(tmp_path, d))


def test_bad_regex_and_empty_patterns(tmp_path):
    d = doc()
    rule = next(r for r in d["rules"] if r["id"] == "WEB-003")
    rule["params"]["patterns"] = ["(unclosed"]
    with pytest.raises(RuleError, match="invalid regex"):
        load_rules(write(tmp_path, d))
    rule["params"]["patterns"] = []
    with pytest.raises(RuleError, match="non-empty list"):
        load_rules(write(tmp_path, d))


def test_bad_escalated_severity(tmp_path):
    d = doc()
    rule = next(r for r in d["rules"] if r["id"] == "WEB-004")
    rule["params"]["escalated_severity"] = "extreme"
    with pytest.raises(RuleError, match="escalated_severity"):
        load_rules(write(tmp_path, d))


def test_duplicate_ids(tmp_path):
    d = doc()
    d["rules"].append(copy.deepcopy(d["rules"][0]))
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(write(tmp_path, d))


def test_disabled_flag_preserved(tmp_path):
    d = doc()
    d["rules"][0]["enabled"] = False
    assert load_rules(write(tmp_path, d))[0].enabled is False
    assert load_rules(write(tmp_path, d))[0].as_dict()["enabled"] is False
