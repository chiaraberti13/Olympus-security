"""Tests for Hermes detection, history scanning, SARIF and demo UX."""

import json
import shutil
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.hermes.sarif import to_sarif
from olympus.hermes.scanner import scan_git_history, scan_path, scan_text

runner = CliRunner()
SYNTHETIC_KEY = "AKIA" + "OLYMPUSDEMO00000"


def _git_executable() -> str:
    executable = shutil.which("git")
    assert executable is not None
    return executable


GIT = _git_executable()


def test_regex_masks_known_secret_and_avoids_false_positive() -> None:
    findings = scan_text(f"key={SYNTHETIC_KEY}\nordinary=short", "demo.env")

    assert len(findings) == 1
    assert findings[0].rule == "aws-access-key"
    assert SYNTHETIC_KEY not in findings[0].masked


def test_entropy_threshold_is_configurable() -> None:
    candidate = "aB3dE5gH7jK9mN2pQ4sT6vX8"

    assert scan_text(candidate, "demo", entropy_threshold=3.0)
    assert not scan_text(candidate, "demo", entropy_threshold=8.0)


def test_scan_path_skips_binary_data(tmp_path: Path) -> None:
    (tmp_path / "safe.txt").write_text("ordinary text", encoding="utf-8")
    (tmp_path / "binary").write_bytes(b"\xff\xfe")

    assert scan_path(tmp_path) == []


def test_sarif_contains_mask_only() -> None:
    finding = scan_text(SYNTHETIC_KEY, "demo.env")[0]
    sarif = to_sarif([finding])
    serialized = json.dumps(sarif)

    assert sarif["version"] == "2.1.0"
    assert SYNTHETIC_KEY not in serialized
    assert sarif["runs"][0]["results"][0]["ruleId"] == "aws-access-key"


def test_git_history_scan_finds_removed_synthetic_secret(tmp_path: Path) -> None:
    subprocess.run([GIT, "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run([GIT, "config", "user.email", "demo@example.com"], cwd=tmp_path, check=True)
    subprocess.run([GIT, "config", "user.name", "Olympus Demo"], cwd=tmp_path, check=True)
    secret_file = tmp_path / "demo.env"
    secret_file.write_text(SYNTHETIC_KEY, encoding="utf-8")
    subprocess.run([GIT, "add", "demo.env"], cwd=tmp_path, check=True)
    subprocess.run([GIT, "commit", "-qm", "synthetic fixture"], cwd=tmp_path, check=True)
    secret_file.write_text("removed", encoding="utf-8")
    subprocess.run([GIT, "commit", "-qam", "remove fixture"], cwd=tmp_path, check=True)

    findings = scan_git_history(tmp_path)

    assert any(finding.rule == "aws-access-key" for finding in findings)


def test_hermes_scan_writes_sarif_and_signals_findings(tmp_path: Path) -> None:
    source = tmp_path / "demo.env"
    output = tmp_path / "results.sarif"
    source.write_text(SYNTHETIC_KEY, encoding="utf-8")

    result = runner.invoke(
        app,
        ["hermes", "scan", str(source), "--output", str(output)],
    )

    assert result.exit_code == 1
    assert output.exists()
    assert SYNTHETIC_KEY not in output.read_text(encoding="utf-8")


def test_baseline_suppresses_known_findings(tmp_path: Path) -> None:
    from olympus.hermes.scanner import apply_baseline, load_baseline, scan_text, write_baseline

    findings = scan_text(SYNTHETIC_KEY, "demo.env")
    assert findings
    baseline_path = tmp_path / "baseline.json"
    write_baseline(findings, baseline_path)
    baseline = load_baseline(baseline_path)
    assert apply_baseline(findings, baseline) == []  # all accepted -> none reported


def test_cli_scan_with_baseline_exits_zero(tmp_path: Path) -> None:
    source = tmp_path / "demo.env"
    source.write_text(SYNTHETIC_KEY, encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    out = tmp_path / "r.sarif"
    # First: record the finding as a baseline.
    first = runner.invoke(
        app,
        ["hermes", "scan", str(source), "--output", str(out), "--write-baseline", str(baseline)],
    )
    assert first.exit_code == 1  # finding present on first run
    # Second: with the baseline applied, the known finding is suppressed.
    second = runner.invoke(
        app, ["hermes", "scan", str(source), "--output", str(out), "--baseline", str(baseline)]
    )
    assert second.exit_code == 0, second.output
    assert "0 potential secret" in second.stdout
