"""Unit and CLI tests for Argus search-engine dork generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus.dorks import (
    DorkCategory,
    DorkEngine,
    DorkGenerationError,
    DorkIntel,
    build_dork_asset,
    build_dork_findings,
    export_dork_intel,
    export_dork_queries,
    generate_dorks,
    normalize_domain,
    render_dork_queries,
)
from olympus.cli import app
from olympus.core.enums import AssetType, Severity

runner = CliRunner()


def test_normalize_domain_strips_scheme_and_path() -> None:
    assert normalize_domain("HTTPS://Example.com:443/login?x=1") == "example.com"
    assert normalize_domain("sub.example.com.") == "sub.example.com"


def test_normalize_domain_rejects_garbage() -> None:
    for bad in ("", "nohost", "has space.com"):
        with pytest.raises(DorkGenerationError):
            normalize_domain(bad)


def test_generate_dorks_is_deterministic_and_covers_all_engines() -> None:
    first = generate_dorks("example.com")
    second = generate_dorks("example.com")
    assert [q.to_dict() for q in first.queries] == [q.to_dict() for q in second.queries]
    assert set(first.engines) == {e.value for e in DorkEngine}
    # Every query is scoped to the normalized domain and carries a ready URL.
    assert all(q.url.startswith("https://") for q in first.queries)
    assert any("example.com" in q.query for q in first.queries)


def test_generate_dorks_filters_by_category_and_engine() -> None:
    catalog = generate_dorks(
        "example.com",
        categories=(DorkCategory.LOGIN_PANELS,),
        engines=(DorkEngine.GOOGLE,),
    )
    assert catalog.categories == (DorkCategory.LOGIN_PANELS.value,)
    assert catalog.engines == (DorkEngine.GOOGLE.value,)
    assert len(catalog.queries) == 1


def test_generate_dorks_url_encodes_operators() -> None:
    catalog = generate_dorks(
        "example.com", engines=(DorkEngine.GOOGLE,), categories=(DorkCategory.LOGIN_PANELS,)
    )
    url = catalog.queries[0].url
    assert " " not in url
    assert "site%3Aexample.com" in url


def test_build_dork_asset_metadata() -> None:
    catalog = generate_dorks("example.com")
    asset = build_dork_asset(catalog)
    assert asset.asset_type is AssetType.DOMAIN
    assert asset.hostname == "example.com"
    assert asset.metadata["queries"] == str(len(catalog.queries))
    assert "google" in asset.metadata["engines"]


def test_build_dork_findings_single_info_finding() -> None:
    catalog = generate_dorks("example.com")
    asset = build_dork_asset(catalog)
    findings = build_dork_findings(asset.asset_id, catalog)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert findings[0].asset_id == asset.asset_id


def test_build_dork_findings_empty_catalog() -> None:
    empty = generate_dorks("example.com", categories=(), engines=(DorkEngine.GOOGLE,))
    # An empty category tuple means "no restriction", so force a truly empty set
    # by asking for a category/engine combination that yields nothing.
    truly_empty = generate_dorks(
        "example.com",
        categories=(DorkCategory.CODE_LEAKS,),
        engines=(DorkEngine.SHODAN,),
    )
    assert empty.queries  # sanity: () means "all"
    assert truly_empty.queries == ()
    assert build_dork_findings("AST-1", truly_empty) == []


def test_render_dork_queries_groups_by_engine() -> None:
    catalog = generate_dorks("example.com", engines=(DorkEngine.GOOGLE,))
    text = render_dork_queries(catalog)
    assert text.startswith("# Argus search-engine reconnaissance for example.com")
    assert "## google" in text
    assert text.endswith("\n")


def test_export_dork_intel_and_queries(tmp_path: Path) -> None:
    catalog = generate_dorks("example.com", engines=(DorkEngine.GOOGLE,))
    asset = build_dork_asset(catalog)
    intel = DorkIntel(
        catalog=catalog, asset=asset, findings=build_dork_findings(asset.asset_id, catalog)
    )
    bundle = tmp_path / "sub" / "dorks.json"
    export_dork_intel(intel, bundle)
    assert json.loads(bundle.read_text())["catalog"]["domain"] == "example.com"
    queries = tmp_path / "sub" / "dorks.txt"
    export_dork_queries(catalog, queries)
    assert "## google" in queries.read_text()


def _scope(tmp_path: Path, domain: str = "example.com") -> Path:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"engagement": "t", "allowed_domains": [domain]}), encoding="utf-8")
    return path


def test_cli_dorks_ok(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "dorks",
            "--domain",
            "example.com",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(tmp_path / "log"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["catalog"]["domain"] == "example.com"


def test_cli_dorks_out_of_scope(tmp_path: Path) -> None:
    log = tmp_path / "log"
    result = runner.invoke(
        app,
        [
            "argus",
            "dorks",
            "--domain",
            "evil.test",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(log),
        ],
    )
    assert result.exit_code == 3
    assert log.exists()


def test_cli_dorks_scope_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["argus", "dorks", "--domain", "example.com", "--scope", str(tmp_path / "missing.json")],
    )
    assert result.exit_code == 2


def test_cli_dorks_invalid_domain(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["argus", "dorks", "--domain", "nohost", "--scope", str(_scope(tmp_path))],
    )
    assert result.exit_code == 2


def test_cli_dorks_unknown_category(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "dorks",
            "--domain",
            "example.com",
            "--scope",
            str(_scope(tmp_path)),
            "--category",
            "nope",
        ],
    )
    assert result.exit_code == 2
    assert "unknown category" in result.output


def test_cli_dorks_unknown_engine(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "dorks",
            "--domain",
            "example.com",
            "--scope",
            str(_scope(tmp_path)),
            "--engine",
            "nope",
        ],
    )
    assert result.exit_code == 2
    assert "unknown engine" in result.output


def test_cli_dorks_exports(tmp_path: Path) -> None:
    out = tmp_path / "dorks.json"
    qout = tmp_path / "dorks.txt"
    result = runner.invoke(
        app,
        [
            "argus",
            "dorks",
            "--domain",
            "example.com",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(tmp_path / "log"),
            "--output",
            str(out),
            "--queries-out",
            str(qout),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert qout.exists()
