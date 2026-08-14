"""Atomic Apollo alert export."""

import json
from pathlib import Path

from olympus.core.models import Alert


def export_alerts(alerts: list[Alert], output: Path) -> None:
    """Write core-compatible alerts as a versioned document."""
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_name": "olympus.apollo-alerts",
        "schema_version": "1.0.0",
        "alerts": [alert.model_dump(mode="json") for alert in alerts],
    }
    temporary = output.with_suffix(f"{output.suffix}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
