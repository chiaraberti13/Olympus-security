from performance_budget import evaluate_performance_budget


def test_evaluate_performance_budget_within_thresholds():
    result = evaluate_performance_budget(
        scan_runtime_seconds=120,
        report_render_seconds=8,
        scan_runtime_budget_seconds=300,
        report_render_budget_seconds=15,
    )

    assert result["within_budget"] is True
    assert result["breaches"] == []
    assert result["scan_runtime_seconds"] == 120.0
    assert result["report_render_seconds"] == 8.0


def test_evaluate_performance_budget_detects_breaches_for_scan_and_report():
    result = evaluate_performance_budget(
        scan_runtime_seconds=901,
        report_render_seconds=21,
        scan_runtime_budget_seconds=900,
        report_render_budget_seconds=20,
    )

    assert result["within_budget"] is False
    assert result["breaches"] == [
        {
            "dimension": "scan_runtime",
            "observed_seconds": 901.0,
            "budget_seconds": 900.0,
        },
        {
            "dimension": "report_render",
            "observed_seconds": 21.0,
            "budget_seconds": 20.0,
        },
    ]


def test_evaluate_performance_budget_ignores_report_sla_when_report_not_rendered():
    result = evaluate_performance_budget(
        scan_runtime_seconds=10,
        report_render_seconds=None,
        scan_runtime_budget_seconds=300,
        report_render_budget_seconds=20,
    )

    assert result["within_budget"] is True
    assert result["report_render_seconds"] is None
