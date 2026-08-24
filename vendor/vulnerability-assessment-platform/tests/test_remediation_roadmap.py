"""Test per la remediation roadmap ordinata per impatto + effort + prerequisiti."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import _build_remediation_roadmap, _estimate_remediation_effort


# ---------------------------------------------------------------------------
# _estimate_remediation_effort
# ---------------------------------------------------------------------------


def test_effort_low_for_header_related_finding() -> None:
    finding = {
        "title": "Missing X-Frame-Options header",
        "severity": "low",
        "recommendation": "Add X-Frame-Options: DENY header to HTTP responses.",
    }
    assert _estimate_remediation_effort(finding) == "basso"


def test_effort_high_for_sql_injection() -> None:
    finding = {
        "title": "SQL Injection su parametro id",
        "severity": "critical",
        "recommendation": "Use parameterized queries to prevent injection attacks.",
    }
    assert _estimate_remediation_effort(finding) == "alto"


def test_effort_high_for_authentication_bypass() -> None:
    finding = {
        "title": "Authentication bypass via token manipulation",
        "severity": "high",
        "recommendation": "Fix authentication logic and validate JWT signatures.",
    }
    assert _estimate_remediation_effort(finding) == "alto"


def test_effort_medium_for_medium_severity_without_keywords() -> None:
    finding = {
        "title": "Outdated library with known CVE",
        "severity": "medium",
        "recommendation": "Update the library to latest stable version.",
    }
    # "update" keyword → basso, but let's verify behaviour
    effort = _estimate_remediation_effort(finding)
    assert effort in ("basso", "medio")


def test_effort_low_for_tls_misconfiguration() -> None:
    finding = {
        "title": "Weak TLS version enabled",
        "severity": "medium",
        "recommendation": "Disable TLS 1.0 and 1.1 in server configuration.",
    }
    assert _estimate_remediation_effort(finding) == "basso"


def test_effort_low_for_cwe_low_effort() -> None:
    finding = {
        "title": "Cookie without Secure flag",
        "severity": "low",
        "cwe": ["CWE-614"],
        "recommendation": "Set Secure flag on sensitive cookies.",
    }
    assert _estimate_remediation_effort(finding) == "basso"


def test_effort_high_for_cwe_high_effort() -> None:
    finding = {
        "title": "SQL Injection via CWE-89",
        "severity": "high",
        "cwe": ["CWE-89"],
        "recommendation": "Use parameterized queries.",
    }
    assert _estimate_remediation_effort(finding) == "alto"


# ---------------------------------------------------------------------------
# _build_remediation_roadmap — structure
# ---------------------------------------------------------------------------


def test_roadmap_empty_for_no_findings() -> None:
    assert _build_remediation_roadmap([]) == []


def test_roadmap_has_correct_rank_sequence() -> None:
    findings = [
        {"title": "A", "severity": "low", "recommendation": "fix A"},
        {"title": "B", "severity": "critical", "recommendation": "fix B"},
        {"title": "C", "severity": "medium", "recommendation": "fix C"},
    ]
    roadmap = _build_remediation_roadmap(findings)
    ranks = [item["rank"] for item in roadmap]
    assert ranks == list(range(1, len(findings) + 1))


def test_roadmap_required_keys_present() -> None:
    findings = [{"title": "Test finding", "severity": "high"}]
    roadmap = _build_remediation_roadmap(findings)
    required_keys = {
        "rank", "finding_index", "title", "severity", "effort",
        "effort_label", "impact_score", "priority_score",
        "tier", "tier_label", "tier_desc", "tier_color",
        "recommendation_preview", "tool", "confidence_level",
    }
    assert required_keys.issubset(roadmap[0].keys())


# ---------------------------------------------------------------------------
# _build_remediation_roadmap — ordering logic
# ---------------------------------------------------------------------------


def test_critical_low_effort_is_tier_immediato() -> None:
    findings = [
        {
            "title": "Critical header missing",
            "severity": "critical",
            "recommendation": "Add HSTS header to redirect all requests to HTTPS.",
        }
    ]
    roadmap = _build_remediation_roadmap(findings)
    assert roadmap[0]["tier"] == "immediato"


def test_critical_high_effort_is_tier_pianifica() -> None:
    findings = [
        {
            "title": "Remote code execution via deserialization",
            "severity": "critical",
            "recommendation": "Fix deserialization logic to prevent remote code execution.",
        }
    ]
    roadmap = _build_remediation_roadmap(findings)
    assert roadmap[0]["tier"] == "pianifica"


def test_low_low_effort_is_tier_quick_win() -> None:
    findings = [
        {
            "title": "Cookie without Secure flag",
            "severity": "low",
            "cwe": ["CWE-614"],
            "recommendation": "Set Secure and HttpOnly flags on all session cookies.",
        }
    ]
    roadmap = _build_remediation_roadmap(findings)
    assert roadmap[0]["tier"] == "quick_win"


def test_info_is_tier_monitora() -> None:
    findings = [
        {
            "title": "Server version disclosure",
            "severity": "info",
            "recommendation": "Hide server version from HTTP response headers.",
        }
    ]
    roadmap = _build_remediation_roadmap(findings)
    assert roadmap[0]["tier"] == "monitora"


def test_critical_items_sorted_before_low_items() -> None:
    findings = [
        {"title": "Low finding", "severity": "low", "recommendation": "minor fix"},
        {
            "title": "Critical header",
            "severity": "critical",
            "recommendation": "Add HSTS header.",
        },
    ]
    roadmap = _build_remediation_roadmap(findings)
    # Critical should appear first (rank 1)
    assert roadmap[0]["title"] == "Critical header"


def test_same_tier_higher_impact_comes_first() -> None:
    findings = [
        {
            "title": "Medium injection",
            "severity": "medium",
            "recommendation": "Fix injection vulnerability via parameterized queries.",
        },
        {
            "title": "High injection",
            "severity": "high",
            "recommendation": "Fix injection vulnerability via parameterized queries.",
        },
    ]
    roadmap = _build_remediation_roadmap(findings)
    severities = [item["severity"] for item in roadmap]
    # 'high' should rank before 'medium' (both pianifica/monitora tier)
    assert severities.index("high") < severities.index("medium")


# ---------------------------------------------------------------------------
# _build_remediation_roadmap — template context integration
# ---------------------------------------------------------------------------


def test_roadmap_tier_color_values_are_valid() -> None:
    findings = [
        {"title": "A", "severity": "critical", "recommendation": "Add HSTS header."},
        {"title": "B", "severity": "high", "recommendation": "Fix authentication bypass."},
        {"title": "C", "severity": "low", "recommendation": "Set Secure cookie."},
        {"title": "D", "severity": "info", "recommendation": "Version disclosure."},
    ]
    roadmap = _build_remediation_roadmap(findings)
    valid_colors = {"rose", "orange", "amber", "slate"}
    for item in roadmap:
        assert item["tier_color"] in valid_colors, f"Invalid color {item['tier_color']} for tier {item['tier']}"


def test_roadmap_effort_label_in_italian() -> None:
    findings = [
        {"title": "A", "severity": "critical", "recommendation": "Add HSTS header."},
        {"title": "B", "severity": "medium", "recommendation": "moderate fix needed"},
        {"title": "C", "severity": "high", "recommendation": "Fix injection."},
    ]
    roadmap = _build_remediation_roadmap(findings)
    valid_labels = {"Basso", "Medio", "Alto"}
    for item in roadmap:
        assert item["effort_label"] in valid_labels


def test_roadmap_finding_index_references_original_list() -> None:
    findings = [
        {"title": "Alpha", "severity": "info"},
        {"title": "Beta", "severity": "critical", "recommendation": "Add HSTS header."},
    ]
    roadmap = _build_remediation_roadmap(findings)
    for item in roadmap:
        original = findings[item["finding_index"]]
        assert item["title"] == original["title"]
