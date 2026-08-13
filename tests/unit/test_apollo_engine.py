"""Unit tests for Apollo's rule-matching engine (true/false positive coverage)."""

from __future__ import annotations

from olympus.apollo.engine import match_events, matches
from olympus.apollo.rules import DetectionRule, RuleCondition
from olympus.core.enums import EventType, Source
from olympus.core.models import Event


def _event(event_type: EventType, **raw: str) -> Event:
    return Event(event_type=event_type, source=Source.APOLLO, summary="test event", raw=raw)


def _rule(event_type: EventType, *conditions: RuleCondition) -> DetectionRule:
    return DetectionRule(
        rule_id="RULE-TEST",
        name="Test rule",
        event_type=event_type,
        conditions=list(conditions),
    )


def test_matches_true_positive_on_equals_condition() -> None:
    rule = _rule(EventType.AUTHENTICATION, RuleCondition(field="outcome", equals="failure"))
    event = _event(EventType.AUTHENTICATION, outcome="failure")

    assert matches(rule, event) is True


def test_matches_true_positive_on_contains_condition() -> None:
    rule = _rule(EventType.PROCESS, RuleCondition(field="command_line", contains="whoami"))
    event = _event(EventType.PROCESS, command_line="/bin/sh -c whoami")

    assert matches(rule, event) is True


def test_matches_false_positive_wrong_event_type() -> None:
    rule = _rule(EventType.AUTHENTICATION, RuleCondition(field="outcome", equals="failure"))
    event = _event(EventType.NETWORK, outcome="failure")

    assert matches(rule, event) is False


def test_matches_false_positive_field_missing() -> None:
    rule = _rule(EventType.AUTHENTICATION, RuleCondition(field="outcome", equals="failure"))
    event = _event(EventType.AUTHENTICATION, user="alice")

    assert matches(rule, event) is False


def test_matches_false_positive_equals_value_mismatch() -> None:
    rule = _rule(EventType.AUTHENTICATION, RuleCondition(field="outcome", equals="failure"))
    event = _event(EventType.AUTHENTICATION, outcome="success")

    assert matches(rule, event) is False


def test_matches_false_positive_contains_substring_absent() -> None:
    rule = _rule(EventType.PROCESS, RuleCondition(field="command_line", contains="whoami"))
    event = _event(EventType.PROCESS, command_line="/bin/ls -la")

    assert matches(rule, event) is False


def test_matches_requires_all_conditions_and_semantics() -> None:
    rule = _rule(
        EventType.AUTHENTICATION,
        RuleCondition(field="outcome", equals="failure"),
        RuleCondition(field="user", equals="admin"),
    )
    partial_match = _event(EventType.AUTHENTICATION, outcome="failure", user="alice")
    full_match = _event(EventType.AUTHENTICATION, outcome="failure", user="admin")

    assert matches(rule, partial_match) is False
    assert matches(rule, full_match) is True


def test_matches_no_conditions_matches_any_event_of_that_type() -> None:
    rule = _rule(EventType.DNS)
    event = _event(EventType.DNS, query="olympusdemocorp.example")

    assert matches(rule, event) is True


def test_match_events_filters_to_matching_subset() -> None:
    rule = _rule(EventType.AUTHENTICATION, RuleCondition(field="outcome", equals="failure"))
    events = [
        _event(EventType.AUTHENTICATION, outcome="failure"),
        _event(EventType.AUTHENTICATION, outcome="success"),
        _event(EventType.NETWORK, outcome="failure"),
    ]

    matched = match_events(rule, events)

    assert len(matched) == 1
    assert matched[0] is events[0]
