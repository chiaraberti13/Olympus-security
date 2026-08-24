from fastapi.testclient import TestClient

import app


def test_csp_disallows_inline_scripts_by_default():
    with TestClient(app.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "script-src" in csp
    directives = {}
    for chunk in csp.split(";"):
        directive = chunk.strip()
        if not directive:
            continue
        key, _, value = directive.partition(" ")
        directives[key] = value

    script_src = directives.get("script-src", "")
    style_src = directives.get("style-src", "")
    object_src = directives.get("object-src", "")
    frame_src = directives.get("frame-src", "")
    base_uri = directives.get("base-uri", "")
    form_action = directives.get("form-action", "")
    manifest_src = directives.get("manifest-src", "")
    block_all_mixed_content = "block-all-mixed-content" in directives
    upgrade_insecure_requests = "upgrade-insecure-requests" in directives
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-inline'" not in style_src
    assert script_src == "'self'"
    assert style_src == "'self'"
    assert object_src == "'none'"
    assert frame_src == "'none'"
    assert base_uri == "'self'"
    assert form_action == "'self'"
    assert manifest_src == "'self'"
    assert block_all_mixed_content is True
    assert upgrade_insecure_requests is True


def test_security_headers_include_origin_isolation_baseline():
    with TestClient(app.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.headers.get("Cross-Origin-Opener-Policy") == "same-origin"
    assert response.headers.get("Cross-Origin-Resource-Policy") == "same-origin"
    assert response.headers.get("Origin-Agent-Cluster") == "?1"


def test_permissions_policy_disables_high_risk_browser_capabilities_by_default():
    with TestClient(app.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    permissions_policy = response.headers.get("Permissions-Policy", "")
    expected_fragments = [
        "camera=()",
        "microphone=()",
        "geolocation=()",
        "clipboard-read=()",
        "clipboard-write=()",
        "publickey-credentials-get=()",
        "usb=()",
    ]
    for fragment in expected_fragments:
        assert fragment in permissions_policy
