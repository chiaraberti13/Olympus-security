"""Search-engine reconnaissance ("dork") generation for Argus.

Open-source intelligence frameworks lean heavily on *search-engine dorks* —
carefully crafted queries that surface exposed documents, login panels,
directory listings, leaked credentials and misconfigured cloud storage for a
target. This module turns that tradecraft into a deterministic, **offline**
building block: given an in-scope domain it *builds* a categorized catalog of
ready-to-run queries across several engines (Google, Bing, DuckDuckGo, GitHub
code search, Shodan and Censys).

It never executes a single query. Generation is pure and repeatable, so tests
stay deterministic and the operator decides when — and whether — to run the
resulting links, under their own documented authorization. The output speaks
the shared data contract (:class:`~olympus.core.models.Asset` /
:class:`~olympus.core.models.Finding`) and can be exported both as a JSON
bundle and as an engine-grouped, copy-pasteable ``.txt`` list.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import quote_plus

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding


class DorkEngine(StrEnum):
    """Search or intelligence engine a generated query targets."""

    GOOGLE = "google"
    BING = "bing"
    DUCKDUCKGO = "duckduckgo"
    GITHUB = "github"
    SHODAN = "shodan"
    CENSYS = "censys"


class DorkCategory(StrEnum):
    """Exposure class a query is designed to surface."""

    EXPOSED_DOCUMENTS = "exposed-documents"
    CONFIG_BACKUP = "config-backup"
    DIRECTORY_LISTING = "directory-listing"
    LOGIN_PANELS = "login-panels"
    SECRETS_IN_TEXT = "secrets-in-text"
    ERROR_MESSAGES = "error-messages"
    OPEN_REDIRECT = "open-redirect"
    VCS_EXPOSURE = "vcs-exposure"
    SUBDOMAINS = "subdomains"
    CLOUD_STORAGE = "cloud-storage"
    CODE_LEAKS = "code-leaks"
    EXPOSED_SERVICES = "exposed-services"
    CERTIFICATES = "certificates"


#: Base search URLs per engine; ``{q}`` is replaced with the URL-encoded query.
_ENGINE_SEARCH_URL: dict[DorkEngine, str] = {
    DorkEngine.GOOGLE: "https://www.google.com/search?q={q}",
    DorkEngine.BING: "https://www.bing.com/search?q={q}",
    DorkEngine.DUCKDUCKGO: "https://duckduckgo.com/?q={q}",
    DorkEngine.GITHUB: "https://github.com/search?q={q}&type=code",
    DorkEngine.SHODAN: "https://www.shodan.io/search?query={q}",
    DorkEngine.CENSYS: "https://search.censys.io/search?resource=hosts&q={q}",
}

#: Web-search engines that accept the same Google-style operator dialect.
_WEB_ENGINES: tuple[DorkEngine, ...] = (
    DorkEngine.GOOGLE,
    DorkEngine.BING,
    DorkEngine.DUCKDUCKGO,
)

# Web-search dork templates: each surfaces one exposure class. ``{domain}`` is
# substituted before the query is URL-encoded for every web engine.
_WEB_DORKS: tuple[tuple[DorkCategory, str, str], ...] = (
    (
        DorkCategory.EXPOSED_DOCUMENTS,
        "Indexed office documents that may leak internal or personal data",
        "site:{domain} (filetype:pdf OR filetype:doc OR filetype:docx OR "
        "filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx)",
    ),
    (
        DorkCategory.CONFIG_BACKUP,
        "Configuration, database and backup files served by mistake",
        "site:{domain} (filetype:env OR filetype:cfg OR filetype:conf OR "
        "filetype:ini OR filetype:bak OR filetype:old OR filetype:sql OR filetype:log)",
    ),
    (
        DorkCategory.DIRECTORY_LISTING,
        "Open directory listings exposing files not meant to be browsable",
        'site:{domain} intitle:"index of" (backup OR admin OR config OR ".git")',
    ),
    (
        DorkCategory.LOGIN_PANELS,
        "Administrative and authentication panels reachable from the internet",
        "site:{domain} (inurl:login OR inurl:admin OR inurl:signin OR "
        'inurl:dashboard OR intitle:"login")',
    ),
    (
        DorkCategory.SECRETS_IN_TEXT,
        "Credentials, tokens or private keys accidentally rendered in a page",
        'site:{domain} (intext:"api_key" OR intext:"secret_key" OR '
        'intext:"BEGIN RSA PRIVATE KEY" OR intext:"password=")',
    ),
    (
        DorkCategory.ERROR_MESSAGES,
        "Verbose application or database errors that disclose the stack",
        'site:{domain} (intext:"sql syntax near" OR intext:"Warning: mysql_" OR '
        'intext:"Fatal error" OR intext:"stack trace")',
    ),
    (
        DorkCategory.OPEN_REDIRECT,
        "URL parameters that commonly drive open-redirect and SSRF probes",
        "site:{domain} (inurl:redirect OR inurl:redir OR inurl:url= OR "
        "inurl:next= OR inurl:return=)",
    ),
    (
        DorkCategory.VCS_EXPOSURE,
        "Exposed version-control or metadata directories",
        'site:{domain} (inurl:".git" OR inurl:".svn" OR inurl:".hg" OR inurl:".DS_Store")',
    ),
    (
        DorkCategory.SUBDOMAINS,
        "Indexed hosts under the domain other than the main www site",
        "site:*.{domain} -www",
    ),
    (
        DorkCategory.CLOUD_STORAGE,
        "Public cloud buckets referencing the target brand or domain",
        "site:s3.amazonaws.com OR site:blob.core.windows.net OR "
        'site:storage.googleapis.com "{domain}"',
    ),
)

# Specialized-engine dork templates (GitHub / Shodan / Censys dialects).
_SPECIAL_DORKS: tuple[tuple[DorkEngine, DorkCategory, str, str], ...] = (
    (
        DorkEngine.GITHUB,
        DorkCategory.CODE_LEAKS,
        "Source code mentioning the domain next to credential-like tokens",
        '"{domain}" (password OR api_key OR secret OR token)',
    ),
    (
        DorkEngine.GITHUB,
        DorkCategory.CODE_LEAKS,
        "Committed environment files referencing the domain",
        '"{domain}" filename:.env',
    ),
    (
        DorkEngine.SHODAN,
        DorkCategory.EXPOSED_SERVICES,
        "Internet-exposed services whose hostname matches the domain",
        "hostname:{domain}",
    ),
    (
        DorkEngine.SHODAN,
        DorkCategory.CERTIFICATES,
        "Hosts presenting a TLS certificate for the domain",
        "ssl.cert.subject.cn:{domain}",
    ),
    (
        DorkEngine.CENSYS,
        DorkCategory.CERTIFICATES,
        "Hosts whose leaf certificate common name matches the domain",
        "services.tls.certificates.leaf_data.subject.common_name:{domain}",
    ),
)


class DorkGenerationError(ValueError):
    """Raised when the supplied domain is empty or malformed."""


def normalize_domain(raw_domain: str) -> str:
    """Return a lower-cased, bare domain (no scheme, path, port or trailing dot)."""
    value = raw_domain.strip().lower()
    if "//" in value:
        value = value.split("//", 1)[1]
    value = value.split("/", 1)[0].split("?", 1)[0]
    value = value.split(":", 1)[0].rstrip(".")
    if not value or " " in value or "." not in value:
        raise DorkGenerationError(f"not a valid domain: {raw_domain!r}")
    return value


def _search_url(engine: DorkEngine, query: str) -> str:
    """Build the ready-to-open search URL for ``query`` on ``engine``."""
    return _ENGINE_SEARCH_URL[engine].format(q=quote_plus(query))


@dataclass(frozen=True)
class DorkQuery:
    """A single ready-to-run reconnaissance query for one engine."""

    engine: DorkEngine
    category: DorkCategory
    description: str
    query: str
    url: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serializable view of the query."""
        return {
            "engine": self.engine.value,
            "category": self.category.value,
            "description": self.description,
            "query": self.query,
            "url": self.url,
        }


@dataclass(frozen=True)
class DorkCatalog:
    """The full, deterministic catalog of dorks generated for one domain."""

    domain: str
    queries: tuple[DorkQuery, ...]

    @property
    def engines(self) -> tuple[str, ...]:
        """Distinct engines present in the catalog, in first-seen order."""
        seen: list[str] = []
        for query in self.queries:
            if query.engine.value not in seen:
                seen.append(query.engine.value)
        return tuple(seen)

    @property
    def categories(self) -> tuple[str, ...]:
        """Distinct exposure categories present, in first-seen order."""
        seen: list[str] = []
        for query in self.queries:
            if query.category.value not in seen:
                seen.append(query.category.value)
        return tuple(seen)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the catalog."""
        return {
            "domain": self.domain,
            "engines": list(self.engines),
            "categories": list(self.categories),
            "count": len(self.queries),
            "queries": [query.to_dict() for query in self.queries],
        }


def generate_dorks(
    raw_domain: str,
    *,
    categories: tuple[DorkCategory, ...] | None = None,
    engines: tuple[DorkEngine, ...] | None = None,
) -> DorkCatalog:
    """Build the deterministic dork catalog for ``raw_domain``.

    ``categories`` and ``engines`` optionally restrict the output; when both are
    ``None`` the full catalog is produced. Ordering is stable so the result is
    byte-for-byte reproducible.
    """
    domain = normalize_domain(raw_domain)
    category_filter = set(categories) if categories else None
    engine_filter = set(engines) if engines else None

    queries: list[DorkQuery] = []
    for category, description, template in _WEB_DORKS:
        if category_filter is not None and category not in category_filter:
            continue
        query_text = template.format(domain=domain)
        for engine in _WEB_ENGINES:
            if engine_filter is not None and engine not in engine_filter:
                continue
            queries.append(
                DorkQuery(
                    engine=engine,
                    category=category,
                    description=description,
                    query=query_text,
                    url=_search_url(engine, query_text),
                )
            )

    for engine, category, description, template in _SPECIAL_DORKS:
        if category_filter is not None and category not in category_filter:
            continue
        if engine_filter is not None and engine not in engine_filter:
            continue
        query_text = template.format(domain=domain)
        queries.append(
            DorkQuery(
                engine=engine,
                category=category,
                description=description,
                query=query_text,
                url=_search_url(engine, query_text),
            )
        )

    return DorkCatalog(domain=domain, queries=tuple(queries))


def build_dork_asset(catalog: DorkCatalog) -> Asset:
    """Convert the catalog's target domain into a ``core.Asset``."""
    return Asset(
        asset_type=AssetType.DOMAIN,
        hostname=catalog.domain,
        source=Source.ARGUS,
        tags=["argus", "dorks", "search-engine-recon"],
        metadata={
            "queries": str(len(catalog.queries)),
            "engines": ",".join(catalog.engines),
            "categories": ",".join(catalog.categories),
        },
    )


def build_dork_findings(asset_id: str, catalog: DorkCatalog) -> list[Finding]:
    """Record the generated reconnaissance surface as one informational finding."""
    if not catalog.queries:
        return []
    return [
        Finding(
            asset_id=asset_id,
            source=Source.ARGUS,
            title="Search-engine reconnaissance surface catalogued",
            description=(
                f"Generated {len(catalog.queries)} passive search-engine queries across "
                f"{len(catalog.engines)} engine(s) to surface potential exposure for "
                f"{catalog.domain!r}: {', '.join(catalog.categories)}. The queries are "
                "prepared but not executed; review each engine's results under documented "
                "authorization."
            ),
            severity=Severity.INFO,
            evidence=[
                f"domain={catalog.domain}",
                f"engines={','.join(catalog.engines)}",
                f"categories={','.join(catalog.categories)}",
                f"query_count={len(catalog.queries)}",
            ],
            remediation=(
                "Review indexed content for sensitive documents, exposed panels, directory "
                "listings and leaked secrets; request removal or de-indexing where warranted."
            ),
        )
    ]


@dataclass(frozen=True)
class DorkIntel:
    """Bundle of everything Argus generated for one domain, ready for export."""

    catalog: DorkCatalog
    asset: Asset
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole bundle."""
        return {
            "catalog": self.catalog.to_dict(),
            "asset": json.loads(self.asset.model_dump_json()),
            "findings": [json.loads(f.model_dump_json()) for f in self.findings],
        }


def render_dork_queries(catalog: DorkCatalog) -> str:
    """Render the catalog as an engine-grouped, copy-pasteable plain-text list."""
    lines: list[str] = [f"# Argus search-engine reconnaissance for {catalog.domain}"]
    for engine in catalog.engines:
        lines.append("")
        lines.append(f"## {engine}")
        for query in catalog.queries:
            if query.engine.value != engine:
                continue
            lines.append(f"# [{query.category.value}] {query.description}")
            lines.append(query.query)
            lines.append(query.url)
    return "\n".join(lines) + "\n"


def export_dork_intel(intel: DorkIntel, path: Path) -> None:
    """Write the dork-intel bundle (catalog + asset + findings) as JSON to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(intel.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def export_dork_queries(catalog: DorkCatalog, path: Path) -> None:
    """Write the engine-grouped plain-text query list to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_dork_queries(catalog), encoding="utf-8")
