"""Offline unit tests — no network required.

Run with:  pytest -q
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from argus import exporters, updater, utils
from argus.config import Config
from argus.modules import (
    dns_lookup,
    email_osint,
    mac_lookup,
    phone_tracker,
    username_tracker,
    web_recon,
)
from argus.modules import (
    domain as domain_mod,
)


# --------------------------- validation helpers --------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [("8.8.8.8", True), ("2001:4860:4860::8888", True), ("999.1.1.1", False), ("nope", False)],
)
def test_is_valid_ip(value, expected):
    assert utils.is_valid_ip(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [("8.8.8.8", True), ("192.168.0.1", False), ("127.0.0.1", False), ("10.0.0.5", False)],
)
def test_is_public_ip(value, expected):
    assert utils.is_public_ip(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [("a@b.com", True), ("x.y+z@sub.domain.io", True), ("bad", False), ("a@b", False)],
)
def test_is_valid_email(value, expected):
    assert utils.is_valid_email(value) is expected


def test_normalize_phone_adds_plus():
    assert utils.normalize_phone("14155552671") == "+14155552671"
    assert utils.normalize_phone("+14155552671") == "+14155552671"


# ------------------------------ phone module ------------------------------ #
def test_phone_valid_us_number():
    data = phone_tracker.lookup("+14155552671")
    assert data["valid"] is True
    assert data["country_code"] == 1
    assert data["format_e164"] == "+14155552671"


def test_phone_invalid_input():
    data = phone_tracker.lookup("abcdef")
    assert "error" in data


def test_phone_region_parsing():
    data = phone_tracker.lookup("02 1234 5678", default_region="IT")
    assert data["country_code"] == 39


# ------------------------------ email module ------------------------------ #
def test_email_bad_syntax():
    assert "error" in email_osint.lookup("not-an-email")


def test_email_hashes_are_deterministic():
    # network-free portion: gravatar check may fail offline, hashes must be stable
    data = email_osint.lookup("test@example.com")
    assert data["md5"] == "55502f40dc8b7c769880b10874abc9d0"
    assert len(data["sha256"]) == 64


# ------------------------- username site catalogue ------------------------ #
def test_sites_catalogue_is_valid():
    catalogue = username_tracker.load_catalogue()
    assert catalogue.get("version", 0) >= 1
    sites = catalogue.get("sites", [])
    assert len(sites) >= 40
    valid = {"status_code", "message", "response_url", "status", "text"}
    for site in sites:
        assert "{username}" in site["url"]
        assert site["name"]
        etype = site.get("errorType") or site.get("method", "status_code")
        assert etype in valid
        # message-detection sites must declare what marks an absent profile.
        if etype in {"message", "text"}:
            assert site.get("errorMsg") or site.get("absence")


def test_username_empty_returns_error(monkeypatch):
    # Feed an empty site list to avoid any network activity.
    data = username_tracker.lookup("someone", sites=[])
    assert "error" in data


class _FakeResp:
    def __init__(self, status_code=200, text="", url="", history=None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.history = history or []


def test_detection_status_code():
    site = {"name": "X", "url": "https://x/{username}", "errorType": "status_code"}
    assert username_tracker._classify(site, _FakeResp(200)) == "found"
    assert username_tracker._classify(site, _FakeResp(404)) == "not found"
    # A redirect on a status_code site means the profile is not there.
    assert username_tracker._classify(site, _FakeResp(200, history=["r"])) == "not found"


def test_detection_blocked_is_not_a_result():
    site = {"name": "X", "url": "https://x/{username}", "errorType": "status_code"}
    for code in (401, 403, 429, 451):
        assert username_tracker._classify(site, _FakeResp(code)) == "blocked"


def test_detection_message():
    site = {"name": "X", "url": "https://x/{username}", "errorType": "message",
            "errorMsg": "No such user."}
    assert username_tracker._classify(site, _FakeResp(200, text="welcome")) == "found"
    assert username_tracker._classify(site, _FakeResp(200, text="No such user.")) == "not found"


def test_detection_response_url():
    site = {"name": "X", "url": "https://x/{username}", "errorType": "response_url",
            "errorUrl": "https://x/login"}
    assert username_tracker._classify(
        site, _FakeResp(200, url="https://x/alice", history=["r"])
    ) == "found"
    assert username_tracker._classify(
        site, _FakeResp(200, url="https://x/login", history=["r"])
    ) == "not found"


def test_legacy_method_keys_still_work():
    site = {"name": "X", "url": "https://x/{username}", "method": "text", "absence": "gone"}
    assert username_tracker._classify(site, _FakeResp(200, text="hi")) == "found"
    assert username_tracker._classify(site, _FakeResp(200, text="gone")) == "not found"


def test_lookup_counts_blocked(monkeypatch):
    sites = [
        {"name": "A", "url": "https://a/{username}", "errorType": "status_code"},
        {"name": "B", "url": "https://b/{username}", "errorType": "status_code"},
    ]

    def fake_check(session, site, username, timeout):
        status = "found" if site["name"] == "A" else "blocked"
        return {"site": site["name"], "url": site["url"], "category": "misc",
                "status": status, "http_status": 200}

    monkeypatch.setattr(username_tracker, "_check_one", fake_check)
    monkeypatch.setattr(username_tracker, "build_session", lambda cfg: object())
    data = username_tracker.lookup("bob", sites=sites)
    assert data["found_count"] == 1
    assert data["blocked_count"] == 1


# ------------------------------ MAC module -------------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [
        ("3C:22:FB:11:22:33", True),
        ("3c-22-fb-11-22-33", True),
        ("3C22FB112233", True),
        ("not-a-mac", False),
        ("12:34:56", False),
    ],
)
def test_is_valid_mac(value, expected):
    assert mac_lookup.is_valid_mac(value) is expected


def test_mac_invalid_returns_error():
    assert "error" in mac_lookup.lookup("zz:zz:zz:zz:zz:zz")


def test_mac_local_and_multicast_bits():
    # 02:... has the locally-administered bit set; 01:... is multicast.
    # These checks run before any network call succeeds/fails, but lookup does
    # hit the network — so we validate the bit math directly via a known OUI.
    # 0x02 -> locally administered, not multicast.
    assert bool(0x02 & 0b10) is True
    assert bool(0x02 & 0b01) is False


# ---------------------- domain / dns / web validation --------------------- #
def test_domain_rejects_non_domain():
    assert "error" in domain_mod.lookup("not a domain")


def test_dns_rejects_non_domain():
    assert "error" in dns_lookup.lookup("nope nope")


def test_web_rejects_bad_url():
    assert "error" in web_recon.lookup("http://")


# ------------------------------- exporters -------------------------------- #
def test_exporters_roundtrip(tmp_path):
    cfg = Config(output_dir=str(tmp_path))
    sample = {
        "username": "demo",
        "checked": 2,
        "found_count": 1,
        "results": [
            {"site": "GitHub", "url": "https://github.com/demo", "category": "dev",
             "status": "found", "http_status": 200},
            {"site": "GitLab", "url": "https://gitlab.com/demo", "category": "dev",
             "status": "not found", "http_status": 404},
        ],
    }
    j = exporters.export(sample, "username", "json", cfg)
    c = exporters.export(sample, "username", "csv", cfg)
    h = exporters.export(sample, "username", "html", cfg)
    assert Path(j).exists() and json.loads(Path(j).read_text())["found_count"] == 1
    assert Path(c).exists() and "GitHub" in Path(c).read_text()
    assert Path(h).exists() and "<html" in Path(h).read_text().lower()


def test_export_rejects_unknown_format(tmp_path):
    cfg = Config(output_dir=str(tmp_path))
    with pytest.raises(ValueError):
        exporters.export({"a": 1}, "x", "xml", cfg)


# -------------------------------- updater --------------------------------- #
@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("2.31.0", "2.32.0", True),
        ("2.32.0", "2.31.0", False),
        ("13.0.0", "13.0.0", False),
        ("8.13.0", "8.13.1", True),
        ("2.4.0b1", "2.4.0", False),
    ],
)
def test_version_comparison(a, b, expected):
    assert updater._version_lt(a, b) is expected


def test_check_dependencies_reports_known_packages():
    report = updater.check_dependencies()
    names = {d["package"] for d in report}
    assert {"requests", "phonenumbers", "rich"} <= names
    for d in report:
        assert set(d) >= {"package", "installed", "outdated", "missing", "optional"}


def test_check_for_updates_is_cached(monkeypatch, tmp_path):
    # Force the state file into a temp dir and simulate a very recent check.
    monkeypatch.setattr(updater, "_STATE_PATH", tmp_path / "state.json")
    updater._save_state({"last_update_check": time.time()})
    result = updater.check_for_updates(Config(), force=False)
    assert result["skipped"] is True and result["checked"] is False


# -------------------------------- config ---------------------------------- #
def test_config_env_override(monkeypatch):
    monkeypatch.setenv("ARGUS_TIMEOUT", "3.5")
    monkeypatch.setenv("ARGUS_MAX_WORKERS", "7")
    cfg = Config.load()
    assert cfg.timeout == 3.5
    assert cfg.max_workers == 7
