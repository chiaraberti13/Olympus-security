from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_ROOT = REPO_ROOT / "tests"
ALLOWED_HELPERS = ("subject_headers(", "bootstrap_csrf_json_client(")
ALLOWLISTED_OCCURRENCES: dict[str, dict[int, str]] = {
    # Formato: "percorso/relativo.py": {linea: "motivazione"}
    # Usare con parsimonia: prima preferire sempre i helper condivisi.
    "tests/test_compliance.py": {
        43: "Test unitario su Request costruita manualmente per validare precedence header/session in get_subject_id.",
    },
}


def test_no_hardcoded_x_data_subject_headers_outside_shared_helpers():
    """
    Previene regressioni di stile: `x-data-subject` non deve essere hardcoded
    direttamente nei test API/UI ma passare dai helper condivisi.
    """
    violations: list[str] = []

    for file_path in sorted(TESTS_ROOT.glob("test_*.py")):
        if file_path.name == "test_subject_header_lint.py":
            continue
        for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
            if '"x-data-subject"' not in line:
                continue
            if any(helper in line for helper in ALLOWED_HELPERS):
                continue
            relative_path = str(file_path.relative_to(REPO_ROOT))
            if line_number in ALLOWLISTED_OCCURRENCES.get(relative_path, {}):
                continue
            violations.append(f"{file_path.relative_to(REPO_ROOT)}:{line_number}")

    assert not violations, (
        "Trovati header x-data-subject hardcoded fuori dai helper condivisi "
        "subject_headers()/bootstrap_csrf_json_client() e non presenti nella allowlist documentata:\n- "
        + "\n- ".join(violations)
    )
