"""Unit tests for the Vulcan aggregation & report engine."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Alert, Asset, Finding
from olympus.vulcan.aggregate import (
    AggregationError,
    dedupe_findings,
    load_findings,
    rank_findings,
    severity_breakdown,
)
from olympus.vulcan.report import build_report, render_markdown

runner = CliRunner()


def _finding(title: str, severity: Severity, asset_id: str = "AST-1") -> Finding:
    return Finding(asset_id=asset_id, source=Source.ARTEMIS, title=title, severity=severity)


def _write(path: Path, models: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(m.model_dump_json()) for m in models]), encoding="utf-8"
    )
    return path


def test_load_findings_from_array(tmp_path: Path) -> None:
    path = _write(tmp_path / "f.json", [_finding("a", Severity.LOW)])
    loaded = load_findings([path])
    assert len(loaded) == 1
    assert loaded[0].title == "a"


def test_load_findings_accepts_single_object(tmp_path: Path) -> None:
    finding = _finding("solo", Severity.HIGH)
    (tmp_path / "one.json").write_text(finding.model_dump_json(), encoding="utf-8")
    assert len(load_findings([tmp_path / "one.json"])) == 1


def test_load_missing_file_errors(tmp_path: Path) -> None:
    with pytest.raises(AggregationError, match="not found"):
        load_findings([tmp_path / "nope.json"])


def test_load_invalid_payload_errors(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text(json.dumps([{"not": "a finding"}]), encoding="utf-8")
    with pytest.raises(AggregationError, match="failed validation"):
        load_findings([tmp_path / "bad.json"])


def test_dedupe_and_rank() -> None:
    findings = [
        _finding("dup", Severity.LOW),
        _finding("dup", Severity.LOW),
        _finding("crit", Severity.CRITICAL),
    ]
    deduped = dedupe_findings(findings)
    assert len(deduped) == 2
    ranked = rank_findings(deduped)
    assert ranked[0].severity is Severity.CRITICAL  # critical ranks first


def test_severity_breakdown_covers_all_levels() -> None:
    counts = severity_breakdown([_finding("a", Severity.HIGH), _finding("b", Severity.HIGH)])
    assert counts["high"] == 2
    assert counts["info"] == 0


def test_build_report_and_markdown() -> None:
    assets = [Asset(asset_type=AssetType.HOST, hostname="h1", source=Source.ARGUS)]
    findings = [_finding("SQLi", Severity.CRITICAL)]
    alerts = [Alert(event_id="EVT-1", title="brute force", source=Source.APOLLO)]
    report = build_report("eng", assets, findings, alerts)
    summary = report["summary"]
    assert isinstance(summary, dict)
    assert summary["findings"] == 1
    md = render_markdown("eng", assets, findings, alerts)
    assert "# Security report — eng" in md
    assert "SQLi" in md
    assert "brute force" in md


def test_cli_report_end_to_end(tmp_path: Path) -> None:
    findings_path = _write(
        tmp_path / "f.json",
        [_finding("SQLi", Severity.CRITICAL), _finding("SQLi", Severity.CRITICAL)],
    )
    out = tmp_path / "report.json"
    md = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "vulcan", "report", "--engagement", "demo-eng",
            "--findings", str(findings_path), "--output", str(out), "--markdown", str(md),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["findings"] == 1  # deduped
    assert md.exists()


def test_cli_rank(tmp_path: Path) -> None:
    findings_path = _write(
        tmp_path / "f.json", [_finding("low", Severity.LOW), _finding("crit", Severity.CRITICAL)]
    )
    result = runner.invoke(app, ["vulcan", "rank", "--findings", str(findings_path)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["severity"] == "critical"


def test_cli_report_bad_input(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    result = runner.invoke(
        app, ["vulcan", "report", "--engagement", "e", "--findings", str(tmp_path / "bad.json")]
    )
    assert result.exit_code == 2
