"""Unit tests for Apollo's detection testing harness."""

from __future__ import annotations

from olympus.apollo.rules import DetectionRule, RuleCondition
from olympus.apollo.testing import LabeledEvent, run_rule_tests
from olympus.core.enums import EventType, Source
from olympus.core.models import Event

RULE = DetectionRule(
    rule_id="RULE-001",
    name="Repeated authentication failures",
    event_type=EventType.AUTHENTICATION,
    conditions=[RuleCondition(field="outcome", equals="failure")],
)


def _event(event_type: EventType = EventType.AUTHENTICATION, **raw: str) -> Event:
    return Event(event_type=event_type, source=Source.APOLLO, summary="test", raw=raw)


def test_run_rule_tests_all_pass() -> None:
    cases = [
        LabeledEvent(_event(outcome="failure"), should_match=True, label="should fire"),
        LabeledEvent(_event(outcome="success"), should_match=False, label="should not fire"),
    ]

    report = run_rule_tests(RULE, cases)

    assert report.rule_id == "RULE-001"
    assert report.passed is True
    assert report.failures == []


def test_run_rule_tests_reports_missed_expected_match() -> None:
    # Rule requires outcome=failure; this event has no 'outcome' field at
    # all, so the rule under-matches relative to what the test expects.
    cases = [LabeledEvent(_event(user="admin"), should_match=True, label="missed detection")]

    report = run_rule_tests(RULE, cases)

    assert report.passed is False
    assert len(report.failures) == 1
    failure = report.failures[0]
    assert failure.label == "missed detection"
    assert failure.expected is True
    assert failure.actual is False


def test_run_rule_tests_reports_unexpected_match() -> None:
    cases = [LabeledEvent(_event(outcome="failure"), should_match=False, label="false positive")]

    report = run_rule_tests(RULE, cases)

    assert report.passed is False
    failure = report.failures[0]
    assert failure.label == "false positive"
    assert failure.expected is False
    assert failure.actual is True


def test_run_rule_tests_mixed_results_lists_only_failures() -> None:
    cases = [
        LabeledEvent(_event(outcome="failure"), should_match=True, label="ok"),
        LabeledEvent(_event(outcome="failure"), should_match=False, label="broken"),
    ]

    report = run_rule_tests(RULE, cases)

    assert report.passed is False
    assert [f.label for f in report.failures] == ["broken"]


def test_label_defaults_to_event_id_when_not_provided() -> None:
    event = _event(outcome="failure")
    cases = [LabeledEvent(event, should_match=True)]

    report = run_rule_tests(RULE, cases)

    assert report.results[0].label == event.event_id


def test_run_rule_tests_empty_cases_passes_trivially() -> None:
    report = run_rule_tests(RULE, [])
    assert report.passed is True
    assert report.results == []
