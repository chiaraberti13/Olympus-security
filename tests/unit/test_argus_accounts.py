"""Unit tests for Argus account enumeration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.accounts import (
    AccountIntel,
    AccountScanResult,
    SiteRegistryError,
    SiteSpec,
    build_account_assets,
    build_account_finding,
    check_site,
    enumerate_accounts,
    export_account_intel,
    load_site_registry,
)
from olympus.core.enums import AssetType, Severity
from olympus.core.http import HttpRequestError, HttpResponse


class _RoutingClient:
    """Offline HttpClient double: returns a response chosen by URL substring."""

    def __init__(
        self, routes: dict[str, HttpResponse], *, error_hosts: tuple[str, ...] = ()
    ) -> None:
        self._routes = routes
        self._error_hosts = error_hosts

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        for host in self._error_hosts:
            if host in url:
                raise HttpRequestError("boom")
        for key, response in self._routes.items():
            if key in url:
                return response
        return HttpResponse(status_code=404, headers={}, body="")


def _spec(**kw: object) -> SiteSpec:
    base: dict[str, object] = {"name": "S", "url_template": "https://site.example/{username}"}
    base.update(kw)
    return SiteSpec.model_validate(base)


def test_check_site_present() -> None:
    client = _RoutingClient({"site.example": HttpResponse(status_code=200, body="hi")})
    check = check_site("bob", _spec(), client)
    assert check.exists is True
    assert check.status_code == 200


def test_check_site_absent() -> None:
    client = _RoutingClient({"site.example": HttpResponse(status_code=404, body="nope")})
    assert check_site("bob", _spec(), client).exists is False


def test_check_site_unknown_status() -> None:
    client = _RoutingClient({"site.example": HttpResponse(status_code=302, body="")})
    assert check_site("bob", _spec(), client).exists is None


def test_check_site_absent_body_signature() -> None:
    spec = _spec(present_status=[200], absent_body="No such user.")
    client = _RoutingClient({"site.example": HttpResponse(status_code=200, body="No such user.")})
    assert check_site("bob", spec, client).exists is False


def test_check_site_present_body_required() -> None:
    spec = _spec(present_body="Profile of")
    client = _RoutingClient({"site.example": HttpResponse(status_code=200, body="unrelated")})
    assert check_site("bob", spec, client).exists is None


def test_check_site_network_error_is_indeterminate() -> None:
    client = _RoutingClient({}, error_hosts=("site.example",))
    check = check_site("bob", _spec(), client)
    assert check.exists is None
    assert check.status_code is None


def test_check_site_extracts_metadata_when_requested() -> None:
    spec = _spec(metadata_patterns={"bio": r"<bio>([^<]*)</bio>"})
    client = _RoutingClient(
        {"site.example": HttpResponse(status_code=200, body="<bio>hello</bio>")}
    )
    check = check_site("bob", spec, client, want_metadata=True)
    assert check.metadata == {"bio": "hello"}


def test_metadata_not_extracted_without_flag() -> None:
    spec = _spec(metadata_patterns={"bio": r"<bio>([^<]*)</bio>"})
    client = _RoutingClient(
        {"site.example": HttpResponse(status_code=200, body="<bio>hello</bio>")}
    )
    assert check_site("bob", spec, client, want_metadata=False).metadata == {}


def test_enumerate_and_build_assets() -> None:
    specs = [
        _spec(name="A", url_template="https://a.example/{username}"),
        _spec(name="B", url_template="https://b.example/{username}"),
    ]
    client = _RoutingClient(
        {
            "a.example": HttpResponse(status_code=200, body="ok"),
            "b.example": HttpResponse(status_code=404, body="no"),
        }
    )
    result = enumerate_accounts("bob", specs, client)
    assert len(result.existing()) == 1
    assets = build_account_assets(result)
    assert len(assets) == 1
    assert assets[0].asset_type is AssetType.ACCOUNT
    assert assets[0].metadata["site"] == "A"


def test_build_finding_severity_scales_with_hits() -> None:
    checks_result = AccountScanResult(
        handle="bob",
        checks=[
            check_site(
                "bob",
                _spec(name=str(i), url_template=f"https://s{i}.example/{{username}}"),
                _RoutingClient({f"s{i}.example": HttpResponse(status_code=200, body="ok")}),
            )
            for i in range(3)
        ],
    )
    finding = build_account_finding("AST-2026-00001", checks_result)
    assert finding is not None
    assert finding.severity is Severity.MEDIUM


def test_build_finding_none_when_no_hits() -> None:
    result = AccountScanResult(handle="bob", checks=[])
    assert build_account_finding("AST-2026-00001", result) is None


def test_load_registry_ok(tmp_path: Path) -> None:
    path = tmp_path / "sites.json"
    path.write_text(
        json.dumps([{"name": "X", "url_template": "https://x.example/{username}"}]),
        encoding="utf-8",
    )
    specs = load_site_registry(path)
    assert specs[0].name == "X"


def test_load_registry_not_found(tmp_path: Path) -> None:
    with pytest.raises(SiteRegistryError, match="not found"):
        load_site_registry(tmp_path / "missing.json")


def test_load_registry_not_a_list(tmp_path: Path) -> None:
    path = tmp_path / "sites.json"
    path.write_text(json.dumps({"name": "x"}), encoding="utf-8")
    with pytest.raises(SiteRegistryError, match="must contain a JSON array"):
        load_site_registry(path)


def test_load_registry_invalid_spec(tmp_path: Path) -> None:
    path = tmp_path / "sites.json"
    path.write_text(json.dumps([{"name": "x"}]), encoding="utf-8")  # missing url_template
    with pytest.raises(SiteRegistryError, match="failed validation"):
        load_site_registry(path)


def test_export_intel_roundtrips(tmp_path: Path) -> None:
    client = _RoutingClient({"site.example": HttpResponse(status_code=200, body="ok")})
    result = enumerate_accounts("bob", [_spec()], client)
    assets = build_account_assets(result)
    finding = build_account_finding(assets[0].asset_id, result)
    intel = AccountIntel(result=result, assets=assets, findings=[finding] if finding else [])
    out = tmp_path / "intel.json"
    export_account_intel(intel, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["assets"][0]["asset_type"] == "account"
    assert loaded["scan"]["handle"] == "bob"
