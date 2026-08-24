import pytest

from config import settings
from scanner_engine import ScanValidationError, validate_nmap_target, validate_target


def test_validate_target_accepts_valid_domain():
    assert validate_target("example.com") == "example.com"


def test_validate_target_accepts_https_url():
    assert validate_target("https://example.com") == "https://example.com"


@pytest.mark.parametrize("target", ["", " ", "ht!tp://bad", "http://"])
def test_validate_target_rejects_invalid_targets(target):
    with pytest.raises(ScanValidationError):
        validate_target(target)


def test_validate_nmap_target_accepts_cidr():
    assert validate_nmap_target("192.168.1.0/24") == "192.168.1.0/24"


def test_validate_nmap_target_accepts_url_hostname():
    assert validate_nmap_target("https://example.com") == "example.com"


def test_validate_nmap_target_accepts_ip_range():
    assert validate_nmap_target("192.168.1.10-20") == "192.168.1.10-20"


@pytest.mark.parametrize("target", ["invalid target", "256.1.1.1", "192.168.1.20-10"])
def test_validate_nmap_target_rejects_invalid(target):
    with pytest.raises(ScanValidationError):
        validate_nmap_target(target)


@pytest.fixture
def production_allowlist():
    original_env = settings.app_env
    original_allowlist = list(settings.target_allowlist)
    object.__setattr__(settings, "app_env", "production")
    object.__setattr__(settings, "target_allowlist", ["example.com", "10.0.0.0/8"])
    try:
        yield
    finally:
        object.__setattr__(settings, "app_env", original_env)
        object.__setattr__(settings, "target_allowlist", original_allowlist)


def test_validate_target_allows_domain_in_production_allowlist(production_allowlist):
    assert validate_target("https://app.example.com") == "https://app.example.com"


def test_validate_target_blocks_domain_outside_production_allowlist(production_allowlist):
    with pytest.raises(ScanValidationError):
        validate_target("https://evil.com")


def test_validate_nmap_target_allows_cidr_in_production_allowlist(production_allowlist):
    assert validate_nmap_target("10.1.0.0/16") == "10.1.0.0/16"


def test_validate_nmap_target_blocks_cidr_outside_production_allowlist(production_allowlist):
    with pytest.raises(ScanValidationError):
        validate_nmap_target("172.16.0.0/16")
