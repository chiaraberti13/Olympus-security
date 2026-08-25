"""Tests for the shared authorization, limits, cancellation, and redaction policy."""

from __future__ import annotations

import json

import pytest

from olympus.core.execution import (
    AuthorizationRequiredError,
    CancellationRequested,
    CancellationToken,
    ExecutionPolicy,
    ExecutionPolicyError,
    NeverCancelled,
    StructuredAuditRecord,
    redact_mapping,
)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0),
        ("deadline_seconds", 0),
        ("max_concurrency", 65),
        ("retries", 6),
        ("backoff_seconds", -1),
        ("min_interval_seconds", 61),
    ],
)
def test_policy_rejects_unsafe_resource_values(field: str, value: object) -> None:
    with pytest.raises(ExecutionPolicyError, match=field):
        ExecutionPolicy(**{field: value})  # type: ignore[arg-type]


def test_policy_authorizes_before_invoking_scope_gate() -> None:
    calls: list[str] = []
    denied = ExecutionPolicy(authorized=False)

    with pytest.raises(AuthorizationRequiredError):
        denied.authorize_target("lookup", "example.com", calls.append)
    assert calls == []

    ExecutionPolicy(authorized=True).authorize_target("lookup", "example.com", calls.append)
    assert calls == ["example.com"]


def test_cancellation_is_thread_safe_and_observed() -> None:
    policy = ExecutionPolicy()
    policy.check_cancellation(NeverCancelled())
    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        policy.check_cancellation(token)


def test_structured_audit_redacts_nested_secrets_and_url_queries() -> None:
    raw = {
        "api_key": "top-secret",
        "request": {
            "url": "https://api.example/v1?token=abc&target=example.com",
            "password": "also-secret",
        },
    }
    redacted = redact_mapping(raw)
    assert redacted["api_key"] == "[REDACTED]"
    request = redacted["request"]
    assert isinstance(request, dict)
    assert "[REDACTED]" in request.values()
    assert "abc" not in request["url"]
    assert "target=example.com" in request["url"]

    record = StructuredAuditRecord(
        timestamp="2026-08-25T00:00:00Z",
        execution_id="EXEC-1",
        action="request",
        outcome="blocked",
        metadata=raw,
    )
    serialized = record.to_json()
    assert "top-secret" not in serialized
    assert json.loads(serialized)["metadata"]["api_key"] == "[REDACTED]"
