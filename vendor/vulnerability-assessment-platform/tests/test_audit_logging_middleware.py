import asyncio

import pytest
from fastapi import Request

import app


def _build_http_request() -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/scans",
        "raw_path": b"/scans",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive=_receive)


def test_audit_middleware_returns_499_on_client_disconnect(monkeypatch):
    middleware = app.AuditLoggingMiddleware(app.app)
    request = _build_http_request()
    monkeypatch.setattr(request, "is_disconnected", lambda: asyncio.sleep(0, result=True))

    async def _call_next(_request):
        raise RuntimeError("No response returned.")

    response = asyncio.run(middleware.dispatch(request, _call_next))
    assert response.status_code == 499


def test_audit_middleware_reraises_runtime_error_when_client_connected(monkeypatch):
    middleware = app.AuditLoggingMiddleware(app.app)
    request = _build_http_request()
    monkeypatch.setattr(request, "is_disconnected", lambda: asyncio.sleep(0, result=False))

    async def _call_next(_request):
        raise RuntimeError("No response returned.")

    with pytest.raises(RuntimeError, match="No response returned."):
        asyncio.run(middleware.dispatch(request, _call_next))
