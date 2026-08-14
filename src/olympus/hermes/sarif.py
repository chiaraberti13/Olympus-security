"""SARIF 2.1.0 serialization for Hermes findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from olympus.hermes.scanner import SecretFinding


def to_sarif(findings: list[SecretFinding]) -> dict[str, Any]:
    """Build a SARIF document containing masked values only."""
    rules = sorted({finding.rule for finding in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Olympus Hermes",
                    "rules": [{"id": rule} for rule in rules],
                }
            },
            "results": [{
                "ruleId": finding.rule,
                "message": {"text": f"Potential secret detected: {finding.masked}"},
                "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": finding.line},
                }}],
            } for finding in findings],
        }],
    }


def write_sarif(findings: list[SecretFinding], output: Path) -> None:
    """Write SARIF atomically."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(f"{output.suffix}.tmp")
    temporary.write_text(json.dumps(to_sarif(findings), indent=2) + "\n", encoding="utf-8")
    temporary.replace(output)
