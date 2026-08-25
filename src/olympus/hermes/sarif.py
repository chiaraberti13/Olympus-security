"""SARIF 2.1.0 serialization for Hermes findings."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from olympus.hermes.scanner import SecretFinding


def to_sarif(findings: list[SecretFinding]) -> dict[str, Any]:
    """Build a SARIF document containing masked values only."""
    rules = sorted({finding.rule for finding in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Olympus Hermes",
                        "rules": [{"id": rule} for rule in rules],
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule,
                        "message": {"text": f"Potential secret detected: {finding.masked}"},
                        "partialFingerprints": {"olympusSecretFingerprint": finding.fingerprint},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.path},
                                    "region": {"startLine": finding.line},
                                }
                            }
                        ],
                    }
                    for finding in findings
                ],
            }
        ],
    }


def write_sarif(findings: list[SecretFinding], output: Path) -> None:
    """Write masked SARIF through a unique atomic temporary file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(to_sarif(findings), indent=2) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
