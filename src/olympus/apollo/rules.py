"""Detection rule schema, YAML loading, and MITRE ATT&CK mapping.

A rule is a small, declarative match spec over `core.Event`: which
`event_type` to match, plus simple field-equality/substring conditions
against `Event.raw`. Rules are the unit both the matching engine (T-132)
and the detection-testing harness (T-134) operate on.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from olympus.core.enums import EventType, Severity

MITRE_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


class RuleError(Exception):
    """Raised when a rule file is missing, unreadable, malformed or invalid."""


class RuleCondition(BaseModel):
    """A single field-match condition against ``Event.raw``."""

    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1)
    equals: str | None = None
    contains: str | None = None

    @model_validator(mode="after")
    def _exactly_one_operator(self) -> RuleCondition:
        """Ensure exactly one of ``equals``/``contains`` is set (never both, never neither)."""
        operators = [value for value in (self.equals, self.contains) if value is not None]
        if len(operators) != 1:
            raise ValueError("condition must set exactly one of 'equals' or 'contains'")
        return self


class DetectionRule(BaseModel):
    """A declarative detection rule mapped to a MITRE ATT&CK technique."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    event_type: EventType
    mitre_technique_id: str | None = None
    conditions: list[RuleCondition] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM

    @field_validator("mitre_technique_id")
    @classmethod
    def _validate_mitre_id(cls, value: str | None) -> str | None:
        """Ensure the MITRE technique id, when present, looks like T1234[.001]."""
        if value is not None and not MITRE_TECHNIQUE_PATTERN.match(value):
            raise ValueError("mitre_technique_id must look like 'T1234' or 'T1234.001'")
        return value


def _parse_rule(raw: Any, path: Path) -> DetectionRule:
    if not isinstance(raw, dict):
        raise RuleError(f"rule file {path} must contain a YAML mapping")
    try:
        return DetectionRule.model_validate(raw)
    except ValidationError as exc:
        raise RuleError(f"rule file {path} failed validation: {exc}") from exc


def load_rule(path: Path) -> DetectionRule:
    """Load and validate a single YAML detection rule file."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuleError(f"rule file not found: {path}") from exc
    except OSError as exc:
        raise RuleError(f"rule file could not be read: {path} ({exc})") from exc

    try:
        raw = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise RuleError(f"rule file is not valid YAML: {path} ({exc})") from exc

    return _parse_rule(raw, path)


def load_rules(directory: Path) -> list[DetectionRule]:
    """Load every ``*.yml``/``*.yaml`` rule file in ``directory``, sorted by path."""
    paths = sorted(
        path for pattern in ("*.yml", "*.yaml") for path in directory.glob(pattern)
    )
    return [load_rule(path) for path in paths]
