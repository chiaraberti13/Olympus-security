#!/usr/bin/env python3
"""Generate OpenAPI 3.0 spec from FastAPI app."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import app  # noqa: E402

OUTPUT_PATH = ROOT / "docs" / "openapi" / "openapi.json"


def main() -> None:
    schema = app.openapi()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(schema, indent=2, ensure_ascii=False))
    print(f"OpenAPI schema written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
