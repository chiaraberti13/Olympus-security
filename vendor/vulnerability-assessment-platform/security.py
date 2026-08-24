#!/usr/bin/env python3
"""Security utilities for Vulnerability Assessment Platform."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import logging
import re
import secrets
from typing import Any, Dict, Optional

import structlog
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from jose import JWTError, jwt
from passlib.exc import UnknownHashError
from passlib.context import CryptContext
from starlette.requests import Request

from config import settings


pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

audit_logger = structlog.get_logger("vap.audit")
_SENSITIVE_KEY_RE = re.compile(
    r"(password|secret|token|api[_-]?key|authorization|cookie|session|credential)",
    re.IGNORECASE,
)


def configure_structlog() -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def hash_api_key(raw_key: str) -> str:
    return pwd_context.hash(raw_key)


def verify_api_key(raw_key: str) -> bool:
    if not raw_key:
        return False
    if settings.api_key_hash:
        try:
            return pwd_context.verify(raw_key, settings.api_key_hash)
        except (UnknownHashError, ValueError):
            return False
    if settings.api_key:
        return hmac.compare_digest(raw_key, settings.api_key)
    return False


def redact_api_key(raw_key: Optional[str]) -> str:
    if not raw_key:
        return ""
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:10]}"


def redact_sensitive_data(data: Any) -> Any:
    """Recursively redact sensitive values in nested payloads."""
    if isinstance(data, dict):
        redacted: Dict[Any, Any] = {}
        for key, value in data.items():
            key_text = str(key)
            if _SENSITIVE_KEY_RE.search(key_text):
                lower_key = key_text.lower()
                if "api" in lower_key and "key" in lower_key:
                    redacted[key] = redact_api_key(str(value)) if value else ""
                else:
                    redacted[key] = "<redacted>"
                continue
            redacted[key] = redact_sensitive_data(value)
        return redacted
    if isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    if isinstance(data, tuple):
        return tuple(redact_sensitive_data(item) for item in data)
    return data


csrf_serializer = URLSafeTimedSerializer(settings.csrf_secret, salt="vap-csrf")


def generate_csrf_token() -> str:
    return csrf_serializer.dumps(secrets.token_urlsafe(16))


def validate_csrf_token(token: str, cookie_token: str) -> None:
    if not token or not cookie_token:
        raise ValueError("Token CSRF mancante")
    if not hmac.compare_digest(token, cookie_token):
        raise ValueError("Token CSRF non valido")
    csrf_serializer.loads(token, max_age=settings.csrf_token_ttl_seconds)


def create_access_token(subject: str, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_exp_minutes)).timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> Dict[str, Any]:
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )


def extract_bearer_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip()


def get_request_ip(request: Request) -> str:
    trusted_proxy_ip = settings.trusted_proxy_ip
    if trusted_proxy_ip and request.client and request.client.host == trusted_proxy_ip:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def log_audit_event(event: str, request: Optional[Request] = None, **data: Any) -> None:
    if not settings.audit_logging_enabled:
        return
    payload = redact_sensitive_data(dict(data))
    if request:
        payload.update(
            {
                "ip": get_request_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "path": request.url.path,
                "method": request.method,
            }
        )
    payload.update({"event": event, "environment": settings.app_env})
    audit_logger.info(**payload)


def require_jwt_configuration() -> None:
    if settings.jwt_required and not settings.jwt_secret:
        raise RuntimeError("VAP_JWT_SECRET è richiesto quando JWT è obbligatorio.")


def current_security_settings() -> Dict[str, Any]:
    data = asdict(settings)
    data.pop("api_key", None)
    data.pop("api_key_hash", None)
    data.pop("csrf_secret", None)
    data.pop("jwt_secret", None)
    data.pop("sqlcipher_key", None)
    return data


def verify_jwt_token(token: str) -> Dict[str, Any]:
    try:
        return decode_access_token(token)
    except (JWTError, ValueError) as exc:
        raise ValueError("JWT non valido") from exc


def validate_csrf_request(request: Request, token: str) -> None:
    cookie_token = request.cookies.get(settings.csrf_cookie_name, "")
    try:
        validate_csrf_token(token, cookie_token)
    except (BadSignature, SignatureExpired, ValueError) as exc:
        raise ValueError("Verifica CSRF fallita") from exc
