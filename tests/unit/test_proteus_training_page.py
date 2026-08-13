"""Unit tests for Proteus's static training page.

These tests are the automated guardrail for the platform's non-negotiable
rule: Proteus must never be able to collect a real credential. Any future
change that adds a form/input to this page must fail these tests.
"""

from __future__ import annotations

from olympus.proteus.training_page import TRAINING_PAGE_TITLE, render_training_page


def test_training_page_discloses_the_exercise() -> None:
    page = render_training_page("Q3 Awareness Campaign")
    assert "simulated phishing exercise" in page
    assert "Q3 Awareness Campaign" in page
    assert TRAINING_PAGE_TITLE in page


def test_training_page_never_contains_a_form() -> None:
    page = render_training_page("Q3 Awareness Campaign")
    assert "<form" not in page.lower()


def test_training_page_never_contains_an_input_field() -> None:
    page = render_training_page("Q3 Awareness Campaign")
    assert "<input" not in page.lower()


def test_training_page_never_requests_credentials() -> None:
    page = render_training_page("Q3 Awareness Campaign").lower()
    for term in ("password", "username", "login", "credit card", "ssn"):
        assert term not in page


def test_training_page_is_well_formed_html() -> None:
    page = render_training_page("Q3 Awareness Campaign")
    assert page.strip().startswith("<!DOCTYPE html>")
    assert "<html" in page
    assert page.strip().endswith("</html>")
