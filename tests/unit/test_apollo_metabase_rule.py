"""Regression tests for the Metabase reset-password SQLi detection rule."""

from __future__ import annotations

from pathlib import Path

from olympus.apollo.demo_data import demo_events, demo_web_events
from olympus.apollo.engine import match_events, matches
from olympus.apollo.rules import load_rule
from olympus.core.enums import Severity

RULE_PATH = Path("examples/input/apollo-rules/metabase-reset-password-sqli.yaml")


def test_rule_loads_with_expected_metadata() -> None:
    rule = load_rule(RULE_PATH)
    assert rule.rule_id == "APOLLO-METABASE-RESET-PW-SQLI-001"
    assert rule.mitre_technique_id == "T1190"
    assert rule.severity is Severity.CRITICAL


def test_rule_fires_on_exploit_event() -> None:
    rule = load_rule(RULE_PATH)
    exploit, _benign = demo_web_events()
    assert matches(rule, exploit) is True


def test_rule_ignores_benign_reset() -> None:
    rule = load_rule(RULE_PATH)
    _exploit, benign = demo_web_events()
    assert matches(rule, benign) is False


def test_rule_ignores_unrelated_auth_events() -> None:
    rule = load_rule(RULE_PATH)
    # The rule must not fire on the authentication demo stream at all.
    assert match_events(rule, demo_events()) == []
