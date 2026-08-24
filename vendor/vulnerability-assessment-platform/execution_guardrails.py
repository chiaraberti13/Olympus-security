from __future__ import annotations

from typing import Set

from scan_configuration import ScanConfigurationV1


class ExecutionGuardrailError(ValueError):
    """Errore di guardrail runtime per avvio scansione."""


def _enabled_tool_count(config: ScanConfigurationV1, scan_type: str) -> int:
    enabled_tools: Set[str] = {
        name.strip().lower()
        for name, override in config.tool_overrides.items()
        if override.enabled
    }
    if enabled_tools:
        return len(enabled_tools)
    if scan_type in {"light", "wordpress"}:
        return 6
    return 8


def enforce_execution_guardrails(
    config: ScanConfigurationV1,
    *,
    scan_type: str,
    actor_role: str,
    kill_switch_enabled: bool,
    max_duration_seconds: int,
    max_requests_per_minute: int,
    max_concurrency: int,
    max_tool_timeout_seconds: int,
    safe_mode_max_depth: int,
    safe_mode_max_payloads: int,
) -> None:
    normalized_role = actor_role.strip().lower()
    if kill_switch_enabled:
        raise ExecutionGuardrailError(
            "Kill switch attivo: nuove scansioni temporaneamente bloccate dall'amministratore."
        )

    if config.runtime.requests_per_minute > max_requests_per_minute:
        raise ExecutionGuardrailError(
            f"requests_per_minute supera il limite consentito ({max_requests_per_minute})."
        )

    if config.runtime.max_concurrency > max_concurrency:
        raise ExecutionGuardrailError(
            f"max_concurrency supera il limite consentito ({max_concurrency})."
        )

    for tool_name, override in config.tool_overrides.items():
        if override.enabled and override.timeout_seconds > max_tool_timeout_seconds:
            raise ExecutionGuardrailError(
                f"Timeout tool '{tool_name}' oltre il limite consentito ({max_tool_timeout_seconds}s)."
            )

    estimated_tools = _enabled_tool_count(config, scan_type.strip().lower())
    average_tool_timeout = max(
        [config.runtime.request_timeout_seconds] + [
            override.timeout_seconds
            for override in config.tool_overrides.values()
            if override.enabled
        ]
    )
    estimated_duration_seconds = estimated_tools * average_tool_timeout
    if estimated_duration_seconds > max_duration_seconds:
        raise ExecutionGuardrailError(
            "Configurazione eccede il budget massimo di durata scansione "
            f"({estimated_duration_seconds}s stimati > {max_duration_seconds}s)."
        )

    if normalized_role != "admin":
        if config.crawler.max_depth > safe_mode_max_depth:
            raise ExecutionGuardrailError(
                f"Safe mode obbligatorio: max_depth deve essere <= {safe_mode_max_depth} per ruoli non admin."
            )

        for tool_name, override in config.tool_overrides.items():
            if override.enabled and override.max_payloads > safe_mode_max_payloads:
                raise ExecutionGuardrailError(
                    "Safe mode obbligatorio: "
                    f"tool '{tool_name}' supera max_payloads consentito ({safe_mode_max_payloads})."
                )


def should_auto_abort_scan(error_count: int, completed_scanners: int, total_scanners: int, threshold: int) -> bool:
    if threshold <= 0:
        return False
    if error_count < threshold:
        return False
    if total_scanners <= 0:
        return True
    error_ratio = error_count / max(1, completed_scanners)
    return error_ratio >= 0.6
