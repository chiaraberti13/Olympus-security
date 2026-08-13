"""Detection rule matching engine: evaluate DetectionRules against Events.

Matching semantics are deliberately simple and explicit: a rule matches an
event when the event's ``event_type`` equals the rule's, and every
condition matches (AND semantics) — no wildcards, no regex, no scoring.
Complexity is expected to grow through more/better rules, not through a
cleverer engine.
"""

from __future__ import annotations

from olympus.apollo.rules import DetectionRule, RuleCondition
from olympus.core.models import Event


def _condition_matches(condition: RuleCondition, event: Event) -> bool:
    """Return ``True`` if ``condition`` matches the value of its field on ``event``."""
    value = event.raw.get(condition.field)
    if value is None:
        return False
    if condition.equals is not None:
        return value == condition.equals
    # RuleCondition's model validator guarantees exactly one of equals/contains
    # is set, so reaching here means contains is not None.
    assert condition.contains is not None  # noqa: S101 (invariant, not input validation)
    return condition.contains in value


def matches(rule: DetectionRule, event: Event) -> bool:
    """Return ``True`` if ``event`` matches ``rule`` (event type + all conditions)."""
    if event.event_type != rule.event_type:
        return False
    return all(_condition_matches(condition, event) for condition in rule.conditions)


def match_events(rule: DetectionRule, events: list[Event]) -> list[Event]:
    """Return the subset of ``events`` that match ``rule``."""
    return [event for event in events if matches(rule, event)]
