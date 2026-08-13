"""Unit tests for Apollo's Alert generation with evidence linking."""

from __future__ import annotations

from olympus.apollo.alerting import build_alert, generate_alerts
from olympus.apollo.rules import DetectionRule, RuleCondition
from olympus.core.enums import EventType, Severity, Source
from olympus.core.models import Event

RULE = DetectionRule(
    rule_id="RULE-001",
    name="Repeated authentication failures",
    description="Flags a failed login attempt.",
    event_type=EventType.AUTHENTICATION,
    mitre_technique_id="T1110",
    severity=Severity.HIGH,
    conditions=[RuleCondition(field="outcome", equals="failure")],
)


def _event(outcome: str) -> Event:
    return Event(
        event_type=EventType.AUTHENTICATION,
        source=Source.APOLLO,
        summary="login attempt",
        raw={"outcome": outcome},
    )


def test_build_alert_copies_rule_metadata() -> None:
    event = _event("failure")
    alert = build_alert(RULE, event)

    assert alert.title == RULE.name
    assert alert.description == RULE.description
    assert alert.severity == Severity.HIGH
    assert alert.source == Source.APOLLO
    assert alert.rule_id == "RULE-001"
    assert alert.mitre_technique_id == "T1110"


def test_build_alert_links_the_triggering_event() -> None:
    event = _event("failure")
    alert = build_alert(RULE, event)

    assert alert.event_ids == [event.event_id]
    assert len(alert.evidence) == 1
    assert alert.evidence[0].reference == event.event_id
    assert RULE.rule_id in alert.evidence[0].description


def test_generate_alerts_one_per_matching_event() -> None:
    events = [_event("failure"), _event("success"), _event("failure")]
    alerts = generate_alerts(RULE, events)

    assert len(alerts) == 2
    assert alerts[0].event_ids == [events[0].event_id]
    assert alerts[1].event_ids == [events[2].event_id]


def test_generate_alerts_no_matches_yields_no_alerts() -> None:
    events = [_event("success")]
    assert generate_alerts(RULE, events) == []
