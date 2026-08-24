import pytest
from pydantic import ValidationError

from scan_configuration import (
    ScanConfigurationPolicyError,
    ScanConfigurationV1,
    validate_scan_configuration_policy_v1,
)


def test_scan_config_normalizes_policy_override_reason_and_approval_reference():
    config = ScanConfigurationV1(
        policy_override_requested=True,
        policy_override_reason="  Necessario per test controllato  ",
        admin_approval_reference="  apr-12345  ",
    )

    assert config.policy_override_reason == "Necessario per test controllato"
    assert config.admin_approval_reference == "APR-12345"


def test_scan_config_rejects_policy_override_reason_without_request():
    with pytest.raises(ValidationError):
        ScanConfigurationV1(
            policy_override_requested=False,
            policy_override_reason="Motivazione non consentita",
        )


def test_scan_config_rejects_invalid_admin_approval_reference_prefix():
    with pytest.raises(ValidationError):
        ScanConfigurationV1(
            policy_override_requested=True,
            policy_override_reason="Richiesta valida",
            admin_approval_reference="REQ-12345",
        )


def test_scan_config_policy_blocks_disallowed_tool_for_scan_type():
    config = ScanConfigurationV1(
        tool_overrides={
            "wpscan": {
                "enabled": True,
                "timeout_seconds": 30,
                "max_payloads": 10,
            }
        }
    )

    with pytest.raises(ScanConfigurationPolicyError):
        validate_scan_configuration_policy_v1(config, scan_type="light", actor_role="admin")


def test_scan_config_policy_requires_approval_for_non_admin_high_risk_tool():
    config = ScanConfigurationV1(
        high_risk_acknowledged=True,
        tool_overrides={
            "sqlmap": {
                "enabled": True,
                "timeout_seconds": 30,
                "max_payloads": 10,
            }
        },
    )

    with pytest.raises(ScanConfigurationPolicyError):
        validate_scan_configuration_policy_v1(config, scan_type="full", actor_role="analyst")
