"""Regression tests for the in-app learning hub (/guida) and shared navigation."""
from fastapi.testclient import TestClient

import app


def test_guide_page_renders_with_core_sections():
    with TestClient(app.app) as client:
        response = client.get("/guida")

    assert response.status_code == 200
    html = response.text

    # Exactly one main landmark and a skip link for keyboard users.
    assert html.count("<main") == 1
    assert "Salta al contenuto della guida" in html
    assert "focus:not-sr-only" in html

    # Dual identity is made explicit.
    assert "Modalità didattica" in html
    assert "Uso professionale" in html

    # Core didactic sections are present.
    assert 'id="modalita"' in html
    assert 'id="percorsi"' in html
    assert 'id="catalogo"' in html
    assert 'id="glossario"' in html

    # Learning paths for every audience.
    assert "Beginner path" in html
    assert "Analyst path" in html
    assert "Professional path" in html


def test_guide_explains_tools_and_step1_choices_with_rich_glossary():
    with TestClient(app.app) as client:
        response = client.get("/guida")

    assert response.status_code == 200
    html = response.text

    # Dedicated "Tool" section documents what each scanner module does.
    assert 'id="tool"' in html
    assert "a cosa serve ogni tool" in html
    for tool_label in ("SQLMap", "Nuclei", "WhatWeb", "WPScan"):
        assert tool_label in html

    # Step 1 choices (objective + experience level) are explained in the guide.
    assert "Lo Step 1 spiegato" in html
    assert "Obiettivo principale" in html
    assert "esposizione iniziale" in html

    # The glossary is substantial (beginner-friendly), not a handful of terms.
    assert "Glossario essenziale" in html
    for term in ("SQL Injection", "XSS", "Payload", "Recon", "Fingerprinting"):
        assert term in html


def test_guide_page_lists_scan_catalog_entries():
    with TestClient(app.app) as client:
        response = client.get("/guida")

    assert response.status_code == 200
    html = response.text

    # Catalog is rendered from the same source of truth as the scan wizard.
    assert "Light Baseline Scan" in html
    assert "Full Stack Assessment" in html
    assert "WordPress Focused Assessment" in html
    # Didactic metadata surfaced for each scan type.
    assert "invasività" in html
    assert "Quando usarla" in html


def test_shared_navigation_is_present_across_pages():
    with TestClient(app.app) as client:
        for path in ["/", "/scans", "/guida", "/privacy-policy", "/terms-of-service"]:
            response = client.get(path)
            assert response.status_code == 200, path
            html = response.text
            assert 'class="site-nav"' in html, f"nav missing on {path}"
            # Primary destinations reachable from every page.
            assert 'href="/guida"' in html, f"guide link missing on {path}"
            assert "Storico" in html, f"history link missing on {path}"


def test_guide_navigation_link_marked_active_on_guide_page():
    with TestClient(app.app) as client:
        response = client.get("/guida")

    assert response.status_code == 200
    html = response.text
    # The active page is announced to assistive tech.
    assert 'aria-current="page"' in html
    assert "site-nav-link-active" in html
