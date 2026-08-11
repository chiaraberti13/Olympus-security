"""Unit tests for Argus -> core.Asset conversion, export and round-trip loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.argus.assets import build_assets, export_assets, load_assets
from olympus.argus.ct import CtRecon
from olympus.argus.recon import DomainRecon
from olympus.core.enums import AssetType, Source

DOMAIN = "olympusdemocorp.example"


def _dns_result() -> DomainRecon:
    return DomainRecon(
        domain=DOMAIN,
        a_records=["203.0.113.10"],
        aaaa_records=["2001:db8::10"],
        mx_records=["10 mail.olympusdemocorp.example"],
        txt_records=["v=spf1 include:_spf.olympusdemocorp.example ~all"],
        spf="v=spf1 include:_spf.olympusdemocorp.example ~all",
        dmarc="v=DMARC1; p=reject",
    )


def _ct_result() -> CtRecon:
    return CtRecon(domain=DOMAIN, subdomains=[DOMAIN, f"www.{DOMAIN}", f"mail.{DOMAIN}"])


def test_build_assets_creates_primary_domain_asset() -> None:
    assets = build_assets(_dns_result(), _ct_result())
    primary = assets[0]

    assert primary.asset_type == AssetType.DOMAIN
    assert primary.hostname == DOMAIN
    assert primary.source == Source.ARGUS
    assert primary.ip_addresses == ["203.0.113.10", "2001:db8::10"]
    assert primary.metadata["spf"].startswith("v=spf1")
    assert primary.metadata["dmarc"].startswith("v=DMARC1")
    assert "mx_records" in primary.metadata


def test_build_assets_adds_one_asset_per_subdomain_without_duplicating_primary() -> None:
    assets = build_assets(_dns_result(), _ct_result())
    hostnames = [asset.hostname for asset in assets]

    assert hostnames.count(DOMAIN) == 1
    assert f"www.{DOMAIN}" in hostnames
    assert f"mail.{DOMAIN}" in hostnames
    assert len(assets) == 3


def test_build_assets_with_no_subdomains_yields_only_primary() -> None:
    assets = build_assets(_dns_result(), CtRecon(domain=DOMAIN, subdomains=[]))
    assert len(assets) == 1
    assert assets[0].hostname == DOMAIN


def test_export_and_load_assets_round_trip(tmp_path: Path) -> None:
    original = build_assets(_dns_result(), _ct_result())
    output_path = tmp_path / "nested" / "argus-assets.json"

    export_assets(original, output_path)
    loaded = load_assets(output_path)

    assert loaded == original
    for asset in loaded:
        assert asset.schema_name == "olympus.asset"
        assert asset.schema_version == "1.0.0"


def test_load_assets_rejects_non_list_payload(tmp_path: Path) -> None:
    path = tmp_path / "argus-assets.json"
    path.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON array"):
        load_assets(path)
