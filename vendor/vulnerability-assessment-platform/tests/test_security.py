import secrets
from types import SimpleNamespace

import pytest

import security


def test_hash_and_verify_api_key_with_plain_key(monkeypatch):
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(api_key="super-secret", api_key_hash=""),
    )

    assert security.verify_api_key("super-secret") is True
    assert security.verify_api_key("wrong") is False


def test_hash_and_verify_api_key_with_hash(monkeypatch):
    api_key_hash = security.hash_api_key("my-key")
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(api_key="", api_key_hash=api_key_hash),
    )

    assert security.verify_api_key("my-key") is True
    assert security.verify_api_key("other") is False


def test_verify_api_key_with_invalid_hash_fails_closed(monkeypatch):
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(api_key="", api_key_hash="not-a-valid-passlib-hash"),
    )

    assert security.verify_api_key("my-key") is False


def test_redact_api_key_returns_hash_prefix():
    redacted = security.redact_api_key("topsecret")

    assert redacted.startswith("sha256:")
    assert "topsecret" not in redacted


def test_csrf_token_validation_roundtrip():
    token = security.generate_csrf_token()

    security.validate_csrf_token(token, token)


@pytest.mark.parametrize("token,cookie_token", [("", "x"), ("x", ""), ("x", "y")])
def test_csrf_token_validation_fails_for_mismatch(token, cookie_token):
    with pytest.raises(ValueError):
        security.validate_csrf_token(token, cookie_token)


def test_access_token_roundtrip(monkeypatch):
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(
            jwt_secret=secrets.token_urlsafe(32),
            jwt_algorithm="HS256",
            jwt_exp_minutes=5,
            jwt_issuer="vap",
            jwt_audience="vap-users",
            api_key="",
            api_key_hash="",
        ),
    )

    token = security.create_access_token("tester")
    decoded = security.decode_access_token(token)

    assert decoded["sub"] == "tester"


def test_get_request_ip_uses_client_ip_without_trusted_proxy(monkeypatch):
    request = SimpleNamespace(
        headers={"x-forwarded-for": "203.0.113.10"},
        client=SimpleNamespace(host="10.0.0.2"),
    )
    monkeypatch.setattr(security, "settings", SimpleNamespace(trusted_proxy_ip=""))
    assert security.get_request_ip(request) == "10.0.0.2"


def test_get_request_ip_uses_forwarded_for_from_trusted_proxy(monkeypatch):
    request = SimpleNamespace(
        headers={"x-forwarded-for": "203.0.113.10, 10.0.0.2"},
        client=SimpleNamespace(host="10.0.0.1"),
    )
    monkeypatch.setattr(security, "settings", SimpleNamespace(trusted_proxy_ip="10.0.0.1"))
    assert security.get_request_ip(request) == "203.0.113.10"


def test_extract_bearer_token():
    request = SimpleNamespace(headers={"Authorization": "Bearer token-123"})
    assert security.extract_bearer_token(request) == "token-123"


def test_extract_bearer_token_returns_none_without_bearer_prefix():
    request = SimpleNamespace(headers={"Authorization": "Basic abc"})
    assert security.extract_bearer_token(request) is None


def test_require_jwt_configuration_raises(monkeypatch):
    monkeypatch.setattr(security, "settings", SimpleNamespace(jwt_required=True, jwt_secret=""))
    with pytest.raises(RuntimeError):
        security.require_jwt_configuration()


def test_current_security_settings_redacts_secrets(monkeypatch):
    monkeypatch.setattr(
        security,
        "asdict",
        lambda _settings: {
            "api_key": "x",
            "api_key_hash": "y",
            "csrf_secret": "z",
            "jwt_secret": "j",
            "sqlcipher_key": "k",
            "other_field": "ok",
        },
    )
    data = security.current_security_settings()
    assert "api_key" not in data
    assert "jwt_secret" not in data
    assert data["other_field"] == "ok"


def test_verify_jwt_token_invalid(monkeypatch):
    monkeypatch.setattr(security, "decode_access_token", lambda _token: (_ for _ in ()).throw(ValueError("bad")))
    with pytest.raises(ValueError):
        security.verify_jwt_token("bad-token")


def test_validate_csrf_request_ok(monkeypatch):
    monkeypatch.setattr(security, "settings", SimpleNamespace(csrf_cookie_name="vap_csrf"))
    monkeypatch.setattr(security, "validate_csrf_token", lambda token, cookie: None)
    request = SimpleNamespace(cookies={"vap_csrf": "t"})
    security.validate_csrf_request(request, "t")


def test_validate_csrf_request_raises(monkeypatch):
    monkeypatch.setattr(security, "settings", SimpleNamespace(csrf_cookie_name="vap_csrf"))

    def _raise(*_args, **_kwargs):
        raise ValueError("bad")

    monkeypatch.setattr(security, "validate_csrf_token", _raise)
    request = SimpleNamespace(cookies={"vap_csrf": "t"})
    with pytest.raises(ValueError):
        security.validate_csrf_request(request, "t")


def test_redact_sensitive_data_masks_nested_secrets():
    payload = {
        "api_key": "my-real-key",
        "nested": {
            "password": "super-secret",
            "notes": "safe",
            "headers": {"Authorization": "Bearer abc"},
        },
        "items": [{"token": "tok"}, {"value": "ok"}],
    }

    redacted = security.redact_sensitive_data(payload)

    assert redacted["api_key"].startswith("sha256:")
    assert redacted["nested"]["password"] == "<redacted>"
    assert redacted["nested"]["headers"]["Authorization"] == "<redacted>"
    assert redacted["items"][0]["token"] == "<redacted>"
    assert redacted["nested"]["notes"] == "safe"


def test_log_audit_event_redacts_sensitive_fields(monkeypatch):
    captured = {}

    class _Logger:
        def info(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(audit_logging_enabled=True, app_env="test", trusted_proxy_ip=""),
    )
    monkeypatch.setattr(security, "audit_logger", _Logger())
    request = SimpleNamespace(
        headers={"user-agent": "pytest"},
        url=SimpleNamespace(path="/api/v1/scans"),
        method="POST",
        client=SimpleNamespace(host="127.0.0.1"),
    )

    security.log_audit_event(
        "scan_created",
        request=request,
        api_key="real-key",
        bearer_token="secret-token",
    )

    assert captured["api_key"].startswith("sha256:")
    assert captured["bearer_token"] == "<redacted>"
