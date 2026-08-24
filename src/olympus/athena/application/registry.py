"""Closed in-process adapter registry for Athena.

Adapter names in a plan are resolved here against a fixed set of factories.
Unknown names are rejected before an assessment is ever persisted, so a plan
can never reference an adapter that does not exist in this repository.
"""

from __future__ import annotations

from collections.abc import Callable

from olympus.athena.adapters.tools.dns_records import DnsRecordsAdapter
from olympus.athena.adapters.tools.web_headers import WebHeadersAdapter
from olympus.athena.adapters.tools.whois import WhoisAdapter
from olympus.athena.ports import ToolRunner
from olympus.core.http import HttpClient

#: The fixed set of adapter factories, keyed by their stable name.
_FACTORIES: dict[str, Callable[[HttpClient], ToolRunner]] = {
    "web-headers": WebHeadersAdapter,
    "dns": DnsRecordsAdapter,
    "whois": WhoisAdapter,
}


class UnknownAdapterError(ValueError):
    """Raised when a plan references an adapter name outside the registry."""


def available_adapters() -> tuple[str, ...]:
    """Return the sorted names of every registered adapter."""
    return tuple(sorted(_FACTORIES))


def resolve_adapters(names: tuple[str, ...], http: HttpClient) -> dict[str, ToolRunner]:
    """Instantiate every named adapter, or raise on the first unknown name."""
    unknown = [name for name in names if name not in _FACTORIES]
    if unknown:
        raise UnknownAdapterError(
            f"unknown adapter(s): {sorted(unknown)}; available: {list(available_adapters())}"
        )
    return {name: _FACTORIES[name](http) for name in names}
