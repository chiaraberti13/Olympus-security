"""Unit tests for Minerva's incident status transition state machine."""

from __future__ import annotations

import pytest

from olympus.core.enums import IncidentStatus
from olympus.core.models import Incident
from olympus.minerva.lifecycle import InvalidTransitionError, is_valid_transition, transition


def _incident(status: IncidentStatus = IncidentStatus.NEW) -> Incident:
    return Incident(title="Test incident", status=status)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (IncidentStatus.NEW, IncidentStatus.TRIAGED),
        (IncidentStatus.TRIAGED, IncidentStatus.CONTAINED),
        (IncidentStatus.CONTAINED, IncidentStatus.RESOLVED),
        (IncidentStatus.RESOLVED, IncidentStatus.CLOSED),
        (IncidentStatus.NEW, IncidentStatus.CLOSED),
        (IncidentStatus.TRIAGED, IncidentStatus.CLOSED),
        (IncidentStatus.CONTAINED, IncidentStatus.CLOSED),
    ],
)
def test_valid_transitions(current: IncidentStatus, target: IncidentStatus) -> None:
    assert is_valid_transition(current, target) is True
    result = transition(_incident(current), target)
    assert result.status == target


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (IncidentStatus.NEW, IncidentStatus.CONTAINED),  # skips TRIAGED
        (IncidentStatus.NEW, IncidentStatus.RESOLVED),  # skips two steps
        (IncidentStatus.TRIAGED, IncidentStatus.NEW),  # backward
        (IncidentStatus.CLOSED, IncidentStatus.NEW),  # backward from closed
        (IncidentStatus.CLOSED, IncidentStatus.CLOSED),  # already closed
        (IncidentStatus.RESOLVED, IncidentStatus.TRIAGED),  # backward
    ],
)
def test_invalid_transitions(current: IncidentStatus, target: IncidentStatus) -> None:
    assert is_valid_transition(current, target) is False
    with pytest.raises(InvalidTransitionError):
        transition(_incident(current), target)


def test_transition_to_closed_sets_closed_at() -> None:
    result = transition(_incident(IncidentStatus.RESOLVED), IncidentStatus.CLOSED)
    assert result.closed_at is not None


def test_transition_does_not_set_closed_at_for_non_closing_transition() -> None:
    result = transition(_incident(IncidentStatus.NEW), IncidentStatus.TRIAGED)
    assert result.closed_at is None


def test_transition_returns_a_new_object_original_unchanged() -> None:
    original = _incident(IncidentStatus.NEW)
    result = transition(original, IncidentStatus.TRIAGED)

    assert original.status == IncidentStatus.NEW
    assert result.status == IncidentStatus.TRIAGED
    assert result is not original


def test_invalid_transition_error_carries_states() -> None:
    with pytest.raises(InvalidTransitionError) as excinfo:
        transition(_incident(IncidentStatus.NEW), IncidentStatus.RESOLVED)
    assert excinfo.value.current == IncidentStatus.NEW
    assert excinfo.value.target == IncidentStatus.RESOLVED
