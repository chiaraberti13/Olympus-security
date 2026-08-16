"""Unit tests for the shared output renderer."""

from olympus.core.output import OutputFormat, render, render_table


def test_render_json() -> None:
    out = render([{"a": 1, "b": "x"}], ["a", "b"], OutputFormat.JSON)
    assert '"a": 1' in out


def test_render_table_contains_headers_and_values() -> None:
    out = render([{"severity": "high", "title": "SQLi"}], ["severity", "title"], OutputFormat.TABLE)
    assert "severity" in out
    assert "SQLi" in out


def test_render_table_direct() -> None:
    out = render_table(["x"], [["1"], ["2"]], title="nums")
    assert "nums" in out
    assert "1" in out and "2" in out
