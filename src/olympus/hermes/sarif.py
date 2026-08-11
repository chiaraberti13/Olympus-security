"""SARIF 2.1.0 report generation for Hermes findings, with secret masking.

Secrets are never written to a report in the clear: every matched value is
masked (a few leading/trailing characters kept, the middle replaced by
``*``) before it reaches the SARIF ``snippet`` field. A full JSON Schema
validation against the official (multi-megabyte) SARIF schema is out of
scope here; :func:`validate_sarif_shape` instead asserts the structural
invariants that make a SARIF log parseable by SARIF-consuming tools
(GitHub code scanning, VS Code SARIF viewer, ...): required top-level
keys, one run per report, and every result referencing a declared rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
DEFAULT_VISIBLE_CHARS = 4


def mask_secret(value: str, *, visible: int = DEFAULT_VISIBLE_CHARS) -> str:
    """Mask ``value``, keeping only the first/last ``visible`` characters."""
    if len(value) <= visible * 2:
        return "*" * len(value)
    middle = "*" * (len(value) - visible * 2)
    return f"{value[:visible]}{middle}{value[-visible:]}"


@dataclass(frozen=True)
class Finding:
    """A normalized, tool-agnostic Hermes finding, ready for SARIF export."""

    rule_id: str
    rule_name: str
    message: str
    file_path: str
    line: int
    column: int
    matched_text: str


def build_sarif_report(findings: list[Finding], *, tool_name: str = "hermes") -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from ``findings``, masking every matched secret."""
    rules_index: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rules_index.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.rule_name},
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": "error",
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                                "snippet": {"text": mask_secret(finding.matched_text)},
                            },
                        }
                    }
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "rules": list(rules_index.values())}},
                "results": results,
            }
        ],
    }


def validate_sarif_shape(report: dict[str, Any]) -> None:
    """Assert that ``report`` has the structural shape of a valid SARIF 2.1.0 log.

    Raises :class:`ValueError` describing the first violation found.
    """
    if report.get("version") != SARIF_VERSION:
        raise ValueError(f"SARIF report must declare version {SARIF_VERSION!r}")
    if "$schema" not in report:
        raise ValueError("SARIF report must declare a $schema")

    runs = report.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise ValueError("SARIF report must have exactly one run")

    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    if not driver.get("name"):
        raise ValueError("SARIF run must declare a tool.driver.name")

    declared_rule_ids = {rule["id"] for rule in driver.get("rules", [])}
    for result in run.get("results", []):
        rule_id = result.get("ruleId")
        if rule_id not in declared_rule_ids:
            raise ValueError(f"result references undeclared ruleId {rule_id!r}")
        if not result.get("locations"):
            raise ValueError(f"result for rule {rule_id!r} has no locations")
