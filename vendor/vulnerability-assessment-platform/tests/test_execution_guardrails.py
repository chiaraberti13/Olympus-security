from execution_guardrails import should_auto_abort_scan


def test_should_auto_abort_scan_when_threshold_and_ratio_met():
    assert should_auto_abort_scan(error_count=3, completed_scanners=4, total_scanners=6, threshold=3)


def test_should_not_auto_abort_scan_when_ratio_low():
    assert not should_auto_abort_scan(error_count=3, completed_scanners=10, total_scanners=10, threshold=3)
