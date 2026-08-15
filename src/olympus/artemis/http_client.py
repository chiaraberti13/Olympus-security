"""HTTP client abstraction for Artemis web recon.

The implementation now lives in :mod:`olympus.core.http`, the single source
of truth shared by every Olympus module that speaks HTTP (Artemis, Argus
account enumeration, the Metabase exposure check). This module re-exports it
so existing ``olympus.artemis.http_client`` imports keep working unchanged.
"""

from __future__ import annotations

from olympus.core.http import (
    HttpClient,
    HttpRequestError,
    HttpResponse,
    UrllibHttpClient,
)

__all__ = ["HttpClient", "HttpRequestError", "HttpResponse", "UrllibHttpClient"]
