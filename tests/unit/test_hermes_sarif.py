"""Unit tests for Hermes SARIF report generation and secret masking."""

from __future__ import annotations

import json

import pytest

from olympus.hermes.sarif import (
    Finding,
    build_sarif_report,
    mask_secret,
    validate_sarif_shape,
)


def test_mask_secret_keeps_only_edges() -> None:
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"


def test_mask_secret_short_value_is_fully_masked() -> None:
    assert mask_secret("abcd") == "****"
    assert mask_secret("abcdefgh") == "********"  # len == visible*2 -> no edges kept


def test_mask_secret_custom_visible_length() -> None:
    assert mask_secret("0123456789", visible=2) == "01******89"


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            rule_id="HERMES-AWS-ACCESS-KEY-ID",
            rule_name="AWS Access Key ID",
            message="AWS Access Key ID detected",
            file_path="config.py",
            line=3,
            column=12,
            matched_text="AKIAIOSFODNN7EXAMPLE",
        ),
        Finding(
            rule_id="HERMES-AWS-ACCESS-KEY-ID",
            rule_name="AWS Access Key ID",
            message="AWS Access Key ID detected",
            file_path="other.py",
            line=1,
            column=1,
            matched_text="AKIAABCDEFGHIJKLMNOP",
        ),
    ]


def test_build_sarif_report_has_valid_shape() -> None:
    report = build_sarif_report(_sample_findings())
    validate_sarif_shape(report)  # must not raise


def test_build_sarif_report_deduplicates_rules() -> None:
    report = build_sarif_report(_sample_findings())
    rules = report["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "HERMES-AWS-ACCESS-KEY-ID"


def test_build_sarif_report_has_one_result_per_finding() -> None:
    report = build_sarif_report(_sample_findings())
    assert len(report["runs"][0]["results"]) == 2


def test_build_sarif_report_never_leaks_raw_secret_value() -> None:
    report = build_sarif_report(_sample_findings())
    serialized = json.dumps(report)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "AKIAABCDEFGHIJKLMNOP" not in serialized
    assert "AKIA************MPLE" in serialized


def test_build_sarif_report_tool_name_is_configurable() -> None:
    report = build_sarif_report(_sample_findings(), tool_name="hermes-ci")
    assert report["runs"][0]["tool"]["driver"]["name"] == "hermes-ci"


def test_build_sarif_report_empty_findings_is_still_valid() -> None:
    report = build_sarif_report([])
    validate_sarif_shape(report)
    assert report["runs"][0]["results"] == []


def test_validate_sarif_shape_rejects_wrong_version() -> None:
    report = build_sarif_report(_sample_findings())
    report["version"] = "2.0.0"
    with pytest.raises(ValueError, match="version"):
        validate_sarif_shape(report)


def test_validate_sarif_shape_rejects_missing_schema() -> None:
    report = build_sarif_report(_sample_findings())
    del report["$schema"]
    with pytest.raises(ValueError, match=r"\$schema"):
        validate_sarif_shape(report)


def test_validate_sarif_shape_rejects_wrong_run_count() -> None:
    report = build_sarif_report(_sample_findings())
    report["runs"] = []
    with pytest.raises(ValueError, match="exactly one run"):
        validate_sarif_shape(report)


def test_validate_sarif_shape_rejects_missing_driver_name() -> None:
    report = build_sarif_report(_sample_findings())
    report["runs"][0]["tool"]["driver"]["name"] = ""
    with pytest.raises(ValueError, match=r"tool\.driver\.name"):
        validate_sarif_shape(report)


def test_validate_sarif_shape_rejects_dangling_rule_reference() -> None:
    report = build_sarif_report(_sample_findings())
    report["runs"][0]["results"][0]["ruleId"] = "UNDECLARED-RULE"
    with pytest.raises(ValueError, match="undeclared ruleId"):
        validate_sarif_shape(report)


def test_validate_sarif_shape_rejects_result_without_locations() -> None:
    report = build_sarif_report(_sample_findings())
    report["runs"][0]["results"][0]["locations"] = []
    with pytest.raises(ValueError, match="no locations"):
        validate_sarif_shape(report)
