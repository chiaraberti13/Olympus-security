"""Bounded application use cases for Apollo detection evaluation."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from pydantic import ValidationError

from olympus.apollo.engine import evaluate
from olympus.apollo.rules import (
    DEFAULT_MAX_RULE_BYTES,
    DEFAULT_MAX_RULES,
    DetectionRule,
    load_rule,
    load_rules,
)
from olympus.core.contracts import validate_contract_header
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.core.models import Alert, Event

DEFAULT_MAX_EVENT_BYTES = 1_000_000
DEFAULT_MAX_EVENTS = 100_000
DEFAULT_MAX_STREAM_BYTES = 100_000_000
DEFAULT_MAX_EVALUATIONS = 1_000_000
DEFAULT_MAX_ALERTS = 100_000
try:
    _NOFOLLOW = os.O_NOFOLLOW
except AttributeError:  # pragma: no cover - Windows lacks this flag
    _NOFOLLOW = 0


@dataclass(frozen=True)
class EventInputError:
    line: int
    message: str


@dataclass(frozen=True)
class ApolloTestRequest:
    rule_path: Path
    event_path: Path
    max_rule_bytes: int = DEFAULT_MAX_RULE_BYTES
    max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES
    deadline_seconds: float = 60.0
    excluded_paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class ApolloRunRequest:
    rules_path: Path
    events_path: Path
    excluded_paths: tuple[Path, ...] = ()
    max_rules: int = DEFAULT_MAX_RULES
    max_rule_bytes: int = DEFAULT_MAX_RULE_BYTES
    max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES
    max_events: int = DEFAULT_MAX_EVENTS
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES
    max_evaluations: int = DEFAULT_MAX_EVALUATIONS
    max_alerts: int = DEFAULT_MAX_ALERTS
    deadline_seconds: float = 600.0


@dataclass(frozen=True)
class ApolloRunOutcome:
    rules: tuple[DetectionRule, ...]
    alerts: tuple[Alert, ...]
    events: int
    duplicates: int
    input_errors: tuple[EventInputError, ...]


@dataclass(frozen=True)
class ApolloApplicationService:
    """Load, validate and evaluate without coupling domain work to Typer."""

    cancellation: Cancellation = field(default_factory=NeverCancelled)

    def test(self, request: ApolloTestRequest) -> ApolloRunOutcome:
        excluded = {path.resolve() for path in request.excluded_paths}
        if request.event_path.resolve() in excluded or request.rule_path.resolve() in excluded:
            raise ValueError("rule/event input conflicts with the alert output path")
        policy = ExecutionPolicy(deadline_seconds=request.deadline_seconds)
        deadline = time.monotonic() + policy.deadline_seconds
        policy.check_cancellation(self.cancellation)
        rule = load_rule(request.rule_path, max_rule_bytes=request.max_rule_bytes)
        policy.check_cancellation(self.cancellation)
        event = _load_single_event(request.event_path, request.max_event_bytes)
        if time.monotonic() >= deadline:
            raise TimeoutError("Apollo test deadline exceeded")
        alerts = evaluate([rule], event)
        return ApolloRunOutcome((rule,), tuple(alerts), 1, 0, ())

    def run(self, request: ApolloRunRequest) -> ApolloRunOutcome:
        _validate_run_limits(request)
        excluded = {path.resolve() for path in request.excluded_paths}
        rules_root = request.rules_path.resolve()
        if request.events_path.resolve() in excluded or any(
            path == rules_root or path.is_relative_to(rules_root) for path in excluded
        ):
            raise ValueError("rule/event input conflicts with the alert output path")
        policy = ExecutionPolicy(deadline_seconds=request.deadline_seconds)
        deadline = time.monotonic() + policy.deadline_seconds

        def progress_check() -> None:
            policy.check_cancellation(self.cancellation)
            if time.monotonic() >= deadline:
                raise TimeoutError("Apollo rule-loading deadline exceeded")

        rules = load_rules(
            request.rules_path,
            max_rules=request.max_rules,
            max_rule_bytes=request.max_rule_bytes,
            progress_check=progress_check,
        )
        events, duplicates, errors = _load_event_stream(
            request.events_path,
            policy=policy,
            cancellation=self.cancellation,
            deadline=deadline,
            max_event_bytes=request.max_event_bytes,
            max_events=request.max_events,
            max_stream_bytes=request.max_stream_bytes,
        )
        alerts: list[Alert] = []
        evaluations = 0
        for event in events:
            policy.check_cancellation(self.cancellation)
            if time.monotonic() >= deadline:
                raise TimeoutError("Apollo evaluation deadline exceeded")
            evaluations += len(rules)
            if evaluations > request.max_evaluations:
                raise ValueError(
                    f"rule/event product exceeds the {request.max_evaluations} evaluation limit"
                )
            fired = evaluate(rules, event)
            if len(alerts) + len(fired) > request.max_alerts:
                raise ValueError(f"alerts exceed the {request.max_alerts} result limit")
            alerts.extend(fired)
        return ApolloRunOutcome(tuple(rules), tuple(alerts), len(events), duplicates, tuple(errors))

    def list_rules(
        self,
        directory: Path,
        *,
        max_rules: int = DEFAULT_MAX_RULES,
        max_rule_bytes: int = DEFAULT_MAX_RULE_BYTES,
        deadline_seconds: float = 60.0,
    ) -> tuple[DetectionRule, ...]:
        policy = ExecutionPolicy(deadline_seconds=deadline_seconds)
        deadline = time.monotonic() + policy.deadline_seconds

        def progress_check() -> None:
            policy.check_cancellation(self.cancellation)
            if time.monotonic() >= deadline:
                raise TimeoutError("Apollo rule-list deadline exceeded")

        return tuple(
            load_rules(
                directory,
                max_rules=max_rules,
                max_rule_bytes=max_rule_bytes,
                progress_check=progress_check,
            )
        )


def _validate_run_limits(request: ApolloRunRequest) -> None:
    limits = (
        (request.max_event_bytes, 1, 10_000_000, "max_event_bytes"),
        (request.max_events, 1, 1_000_000, "max_events"),
        (request.max_stream_bytes, 1, 1_000_000_000, "max_stream_bytes"),
        (request.max_evaluations, 1, 100_000_000, "max_evaluations"),
        (request.max_alerts, 1, 1_000_000, "max_alerts"),
    )
    for value, minimum, maximum, name in limits:
        if not minimum <= value <= maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")


def _open_regular(path: Path) -> BinaryIO:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"event path must be a regular non-symlink file: {path}")
    descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
    return os.fdopen(descriptor, "rb")


def _event_from_json(value: str) -> Event:
    raw: object = json.loads(value)
    if isinstance(raw, dict) and "schema_name" not in raw and "schema_version" not in raw:
        required_legacy = {"event_id", "event_type", "source", "observed_at", "attributes"}
        if not required_legacy.issubset(raw):
            missing = sorted(required_legacy - set(raw))
            raise ValueError(f"legacy event is missing required fields: {missing}")
        raw = {"schema_name": "olympus.event", "schema_version": "1.0.0", **raw}
    validate_contract_header(raw, schema_name="olympus.event")
    try:
        return Event.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False, include_input=False)
        )
        raise ValueError(f"event contract validation failed: {details}") from exc


def _load_single_event(path: Path, max_event_bytes: int) -> Event:
    if not 1 <= max_event_bytes <= 10_000_000:
        raise ValueError("max_event_bytes must be between 1 and 10000000")
    with _open_regular(path) as handle:
        content = handle.read(max_event_bytes + 1)
    if len(content) > max_event_bytes:
        raise ValueError(f"event file exceeds the {max_event_bytes} byte limit")
    try:
        return _event_from_json(content.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("event file must be UTF-8 JSON") from exc


def _load_event_stream(
    path: Path,
    *,
    policy: ExecutionPolicy,
    cancellation: Cancellation,
    deadline: float,
    max_event_bytes: int,
    max_events: int,
    max_stream_bytes: int,
) -> tuple[list[Event], int, list[EventInputError]]:
    events: list[Event] = []
    by_id: dict[str, Event] = {}
    duplicates = 0
    errors: list[EventInputError] = []
    total_bytes = 0
    line_number = 0
    records = 0
    with _open_regular(path) as handle:
        while True:
            policy.check_cancellation(cancellation)
            if time.monotonic() >= deadline:
                raise TimeoutError("Apollo event-stream deadline exceeded")
            line = handle.readline(max_event_bytes + 2)
            if not line:
                break
            line_number += 1
            total_bytes += len(line)
            if total_bytes > max_stream_bytes:
                raise ValueError(f"event stream exceeds the {max_stream_bytes} byte limit")
            if len(line) > max_event_bytes + 1 or (
                len(line) > max_event_bytes and not line.endswith(b"\n")
            ):
                raise ValueError(
                    f"event on line {line_number} exceeds the {max_event_bytes} byte limit"
                )
            if not line.strip():
                continue
            records += 1
            if records > max_events:
                raise ValueError(f"event stream exceeds the {max_events} record limit")
            try:
                event = _event_from_json(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                errors.append(EventInputError(line_number, str(exc)))
                continue
            previous = by_id.get(event.event_id)
            if previous is not None:
                if previous.model_dump(mode="json") != event.model_dump(mode="json"):
                    errors.append(EventInputError(line_number, "conflicting duplicate event_id"))
                else:
                    duplicates += 1
                continue
            by_id[event.event_id] = event
            events.append(event)
    if not events and not errors:
        raise ValueError("event stream contains no events")
    return events, duplicates, errors
