"""Unit tests for Apollo's detection rule schema and YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.apollo.rules import RuleError, load_rule, load_rules
from olympus.core.enums import EventType, Severity

VALID_RULE_YAML = """
rule_id: RULE-001
name: Repeated authentication failures
description: Flags a failed login attempt.
event_type: authentication
mitre_technique_id: T1110
severity: high
conditions:
  - field: outcome
    equals: failure
"""


def test_load_rule_parses_valid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(VALID_RULE_YAML, encoding="utf-8")

    rule = load_rule(path)

    assert rule.rule_id == "RULE-001"
    assert rule.event_type == EventType.AUTHENTICATION
    assert rule.mitre_technique_id == "T1110"
    assert rule.severity == Severity.HIGH
    assert len(rule.conditions) == 1
    assert rule.conditions[0].field == "outcome"
    assert rule.conditions[0].equals == "failure"


def test_load_rule_defaults_severity_and_conditions(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text("rule_id: RULE-002\nname: Minimal rule\nevent_type: network\n")

    rule = load_rule(path)

    assert rule.severity == Severity.MEDIUM
    assert rule.conditions == []
    assert rule.mitre_technique_id is None


def test_load_rule_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="not found"):
        load_rule(tmp_path / "missing.yaml")


def test_load_rule_invalid_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text("rule_id: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleError, match="not valid YAML"):
        load_rule(path)


def test_load_rule_non_mapping_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(RuleError, match="must contain a YAML mapping"):
        load_rule(path)


def test_load_rule_missing_required_field_raises(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text("rule_id: RULE-003\n", encoding="utf-8")
    with pytest.raises(RuleError, match="failed validation"):
        load_rule(path)


def test_load_rule_rejects_unknown_field(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(
        "rule_id: RULE-004\nname: x\nevent_type: network\nbogus_field: 1\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="failed validation"):
        load_rule(path)


def test_load_rule_rejects_malformed_mitre_id(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(
        "rule_id: RULE-005\nname: x\nevent_type: network\nmitre_technique_id: not-a-technique\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="failed validation"):
        load_rule(path)


def test_load_rule_accepts_mitre_id_with_sub_technique(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(
        "rule_id: RULE-006\nname: x\nevent_type: network\nmitre_technique_id: T1110.001\n",
        encoding="utf-8",
    )
    assert load_rule(path).mitre_technique_id == "T1110.001"


def test_condition_rejects_both_operators(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(
        "rule_id: RULE-007\nname: x\nevent_type: network\n"
        "conditions:\n  - field: outcome\n    equals: failure\n    contains: fail\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="failed validation"):
        load_rule(path)


def test_condition_rejects_neither_operator(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(
        "rule_id: RULE-008\nname: x\nevent_type: network\nconditions:\n  - field: outcome\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="failed validation"):
        load_rule(path)


def test_load_rules_loads_every_yaml_file_sorted(tmp_path: Path) -> None:
    (tmp_path / "b.yaml").write_text("rule_id: RULE-B\nname: b\nevent_type: network\n")
    (tmp_path / "a.yml").write_text("rule_id: RULE-A\nname: a\nevent_type: network\n")
    (tmp_path / "not-a-rule.txt").write_text("ignored")

    rules = load_rules(tmp_path)

    assert [rule.rule_id for rule in rules] == ["RULE-A", "RULE-B"]


def test_load_rules_empty_directory_returns_empty_list(tmp_path: Path) -> None:
    assert load_rules(tmp_path) == []
