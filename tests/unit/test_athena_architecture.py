"""Guard the accepted Athena target architecture against accidental omissions."""

from pathlib import Path

ADR = Path("docs/architecture/adr-002-athena-target-architecture.md")


def test_target_architecture_records_required_decisions() -> None:
    document = ADR.read_text(encoding="utf-8")
    required_sections = {
        "## Package boundaries and dependency direction",
        "## Domain contracts",
        "## Ports and adapter contract",
        "## Execution model",
        "## Persistence and recovery",
        "## Authorization, audit, and sensitive data",
        "## CLI and future API/UI boundaries",
        "## Migration strategy",
        "## Delivery slices and acceptance",
    }

    assert "- **Status:** Accepted" in document
    assert required_sections <= set(document.splitlines())


def test_target_architecture_keeps_security_invariants_explicit() -> None:
    document = ADR.read_text(encoding="utf-8")

    for invariant in (
        "existing modules cannot import Athena",
        "Unknown adapters are rejected",
        "owner-only permissions",
        "`..` traversal are rejected",
        "raw discovered secrets are never persisted",
        "no placeholder dashboard is permitted",
        "There is no runtime compatibility layer",
    ):
        assert invariant in document
