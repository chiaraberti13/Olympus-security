"""Enrichment e correlazione delle vulnerabilità."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

from config import settings
from false_positive_model import FalsePositiveModel, build_features
from feed_updater import load_local_kev_catalog, load_local_nvd_index


MITRE_CWE_MAPPING: Dict[str, List[Dict[str, Any]]] = {
    "CWE-79": [
        {
            "technique_id": "T1189",
            "technique_name": "Drive-by Compromise",
            "tactics": ["Initial Access"],
        },
        {
            "technique_id": "T1185",
            "technique_name": "Browser Session Hijacking",
            "tactics": ["Collection"],
        },
    ],
    "CWE-89": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
        },
        {
            "technique_id": "T1213",
            "technique_name": "Data from Information Repositories",
            "tactics": ["Collection"],
        },
    ],
    "CWE-77": [
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactics": ["Execution"],
        }
    ],
    "CWE-78": [
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactics": ["Execution"],
        },
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
        },
    ],
    "CWE-22": [
        {
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "tactics": ["Discovery"],
        },
        {
            "technique_id": "T1005",
            "technique_name": "Data from Local System",
            "tactics": ["Collection"],
        },
    ],
    "CWE-284": [
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        }
    ],
    "CWE-285": [
        {
            "technique_id": "T1548",
            "technique_name": "Abuse Elevation Control Mechanism",
            "tactics": ["Privilege Escalation", "Defense Evasion"],
        }
    ],
    "CWE-306": [
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactics": ["Initial Access"],
        }
    ],
    "CWE-200": [
        {
            "technique_id": "T1592",
            "technique_name": "Gather Victim Host Information",
            "tactics": ["Reconnaissance"],
        }
    ],
    "CWE-312": [
        {
            "technique_id": "T1552",
            "technique_name": "Unsecured Credentials",
            "tactics": ["Credential Access"],
        }
    ],
    "CWE-538": [
        {
            "technique_id": "T1552",
            "technique_name": "Unsecured Credentials",
            "tactics": ["Credential Access"],
        }
    ],
    "CWE-601": [
        {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactics": ["Initial Access"],
        }
    ],
    "CWE-614": [
        {
            "technique_id": "T1539",
            "technique_name": "Steal Web Session Cookie",
            "tactics": ["Credential Access"],
        }
    ],
    "CWE-1004": [
        {
            "technique_id": "T1539",
            "technique_name": "Steal Web Session Cookie",
            "tactics": ["Credential Access"],
        }
    ],
    "CWE-307": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactics": ["Credential Access"],
        }
    ],
    "CWE-326": [
        {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactics": ["Credential Access", "Discovery"],
        }
    ],
    "CWE-319": [
        {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactics": ["Credential Access", "Discovery"],
        }
    ],
    "CWE-1336": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
        },
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactics": ["Execution"],
        },
    ],
    "CWE-94": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
        }
    ],
    "CWE-639": [
        {
            "technique_id": "T1087",
            "technique_name": "Account Discovery",
            "tactics": ["Discovery"],
        }
    ],
    "CWE-942": [
        {
            "technique_id": "T1185",
            "technique_name": "Browser Session Hijacking",
            "tactics": ["Collection"],
        }
    ],
    "CWE-350": [
        {
            "technique_id": "T1584",
            "technique_name": "Compromise Infrastructure",
            "tactics": ["Resource Development"],
        }
    ],
    "CWE-209": [
        {
            "technique_id": "T1592",
            "technique_name": "Gather Victim Host Information",
            "tactics": ["Reconnaissance"],
        }
    ],
    "CWE-530": [
        {
            "technique_id": "T1005",
            "technique_name": "Data from Local System",
            "tactics": ["Collection"],
        }
    ],
    "CWE-1021": [
        {
            "technique_id": "T1185",
            "technique_name": "Browser Session Hijacking",
            "tactics": ["Collection"],
        }
    ],
}

KEYWORD_MITRE_MAPPING: List[Tuple[re.Pattern[str], Dict[str, Any]]] = [
    (
        re.compile(r"sql\s*injection", re.IGNORECASE),
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
        },
    ),
    (
        re.compile(r"xss|cross-site\s*scripting", re.IGNORECASE),
        {
            "technique_id": "T1189",
            "technique_name": "Drive-by Compromise",
            "tactics": ["Initial Access"],
        },
    ),
    (
        re.compile(r"command injection|os injection|rce|remote code execution", re.IGNORECASE),
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactics": ["Execution"],
        },
    ),
    (
        re.compile(r"path traversal|directory traversal|local file inclusion|lfi", re.IGNORECASE),
        {
            "technique_id": "T1005",
            "technique_name": "Data from Local System",
            "tactics": ["Collection"],
        },
    ),
    (
        re.compile(r"brute.?force|credential stuffing|password spraying", re.IGNORECASE),
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactics": ["Credential Access"],
        },
    ),
    (
        re.compile(r"idor|insecure direct object|broken access control", re.IGNORECASE),
        {
            "technique_id": "T1087",
            "technique_name": "Account Discovery",
            "tactics": ["Discovery"],
        },
    ),
    (
        re.compile(r"subdomain takeover|dns takeover", re.IGNORECASE),
        {
            "technique_id": "T1584",
            "technique_name": "Compromise Infrastructure",
            "tactics": ["Resource Development"],
        },
    ),
    (
        re.compile(r"open redirect|url redirect", re.IGNORECASE),
        {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactics": ["Initial Access"],
        },
    ),
    (
        re.compile(r"session hijack|cookie theft|cookie steal", re.IGNORECASE),
        {
            "technique_id": "T1539",
            "technique_name": "Steal Web Session Cookie",
            "tactics": ["Credential Access"],
        },
    ),
    (
        re.compile(r"template injection|ssti", re.IGNORECASE),
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
        },
    ),
    (
        re.compile(r"cors|cross.origin", re.IGNORECASE),
        {
            "technique_id": "T1185",
            "technique_name": "Browser Session Hijacking",
            "tactics": ["Collection"],
        },
    ),
    (
        re.compile(r"exposed.*credential|hardcoded.*password|git.*expos|secret.*expos", re.IGNORECASE),
        {
            "technique_id": "T1552",
            "technique_name": "Unsecured Credentials",
            "tactics": ["Credential Access"],
        },
    ),
    (
        re.compile(r"tls|ssl|cipher|https.*missing|hsts", re.IGNORECASE),
        {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactics": ["Credential Access"],
        },
    ),
]

OWASP_2021_MAPPING: Dict[str, str] = {
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-79": "A03:2021 - Injection",
    "CWE-89": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-77": "A03:2021 - Injection",
    "CWE-78": "A03:2021 - Injection",
    "CWE-200": "A02:2021 - Cryptographic Failures",
    "CWE-312": "A02:2021 - Cryptographic Failures",
    "CWE-319": "A02:2021 - Cryptographic Failures",
    "CWE-326": "A02:2021 - Cryptographic Failures",
    "CWE-611": "A05:2021 - Security Misconfiguration",
    "CWE-306": "A07:2021 - Identification and Authentication Failures",
    "CWE-307": "A07:2021 - Identification and Authentication Failures",
    "CWE-601": "A10:2021 - Server-Side Request Forgery",
}

OWASP_2017_MAPPING: Dict[str, str] = {
    "CWE-89": "A1:2017 - Injection",
    "CWE-77": "A1:2017 - Injection",
    "CWE-78": "A1:2017 - Injection",
    "CWE-79": "A7:2017 - Cross-Site Scripting (XSS)",
    "CWE-200": "A3:2017 - Sensitive Data Exposure",
    "CWE-312": "A3:2017 - Sensitive Data Exposure",
    "CWE-319": "A3:2017 - Sensitive Data Exposure",
    "CWE-611": "A4:2017 - XML External Entities (XXE)",
    "CWE-22": "A5:2017 - Broken Access Control",
    "CWE-284": "A5:2017 - Broken Access Control",
    "CWE-285": "A5:2017 - Broken Access Control",
    "CWE-306": "A2:2017 - Broken Authentication",
    "CWE-307": "A2:2017 - Broken Authentication",
}

OWASP_2025_MAPPING: Dict[str, str] = {
    "CWE-22": "A01:2025 - Broken Access Control",
    "CWE-284": "A01:2025 - Broken Access Control",
    "CWE-285": "A01:2025 - Broken Access Control",
    "CWE-79": "A03:2025 - Injection",
    "CWE-89": "A03:2025 - Injection",
    "CWE-94": "A03:2025 - Injection",
    "CWE-77": "A03:2025 - Injection",
    "CWE-78": "A03:2025 - Injection",
    "CWE-200": "A02:2025 - Cryptographic Failures",
    "CWE-312": "A02:2025 - Cryptographic Failures",
    "CWE-319": "A02:2025 - Cryptographic Failures",
    "CWE-326": "A02:2025 - Cryptographic Failures",
    "CWE-602": "A04:2025 - Insecure Design",
    "CWE-799": "A04:2025 - Insecure Design",
    "CWE-611": "A05:2025 - Security Misconfiguration",
    "CWE-16": "A05:2025 - Security Misconfiguration",
    "CWE-1104": "A06:2025 - Vulnerable and Outdated Components",
    "CWE-306": "A07:2025 - Identification and Authentication Failures",
    "CWE-307": "A07:2025 - Identification and Authentication Failures",
    "CWE-352": "A08:2025 - Software and Data Integrity Failures",
    "CWE-494": "A08:2025 - Software and Data Integrity Failures",
    "CWE-778": "A09:2025 - Security Logging and Monitoring Failures",
    "CWE-117": "A09:2025 - Security Logging and Monitoring Failures",
    "CWE-601": "A10:2025 - Server-Side Request Forgery",
}


@dataclass
class EnrichmentSummary:
    nvd_hits: int = 0
    exploitdb_hits: int = 0


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched = [dict(item) for item in findings]
    summary = EnrichmentSummary()

    _apply_cve_enrichment(enriched, summary)
    _apply_owasp_mapping(enriched)
    _apply_mitre_mapping(enriched)
    _apply_false_positive_model(enriched)
    _apply_correlation(enriched)

    for item in enriched:
        item.setdefault("enrichment_summary", {})
        item["enrichment_summary"].update(
            {"nvd_hits": summary.nvd_hits, "exploitdb_hits": summary.exploitdb_hits}
        )

    return enriched


def _apply_cve_enrichment(findings: List[Dict[str, Any]], summary: EnrichmentSummary) -> None:
    cves = sorted({cve for cve in _extract_cves(findings)})
    if not cves:
        return

    nvd_payload = _fetch_nvd_metadata(cves)
    wpvulndb_payload = _fetch_wpvulndb_metadata(cves)
    exploitdb_payload = _fetch_exploitdb_metadata(cves)
    epss_payload = _fetch_epss_metadata(cves)
    kev_catalog = _fetch_cisa_kev_catalog()

    for finding in findings:
        finding_cves = [cve for cve in finding.get("cve", []) if isinstance(cve, str)]
        nvd_items = [nvd_payload[cve] for cve in finding_cves if cve in nvd_payload]
        exploit_items = [exploitdb_payload[cve] for cve in finding_cves if cve in exploitdb_payload]
        cve_details = []

        if nvd_items:
            summary.nvd_hits += 1
            finding.setdefault("nvd", []).extend(nvd_items)
        if exploit_items:
            summary.exploitdb_hits += 1
            finding.setdefault("exploitdb", []).extend(exploit_items)

        if nvd_items or exploit_items:
            finding["cve_verified"] = True
        elif finding_cves:
            finding["cve_verified"] = False

        for cve in finding_cves:
            nvd = nvd_payload.get(cve, {})
            wpvulndb = wpvulndb_payload.get(cve, {})
            epss = epss_payload.get(cve, {})
            kev = kev_catalog.get(cve, {})
            detail: Dict[str, Any] = {"cve": cve}
            if nvd:
                detail.update(nvd)
            if wpvulndb:
                if not detail.get("fixed_in_version") and wpvulndb.get("fixed_in_version"):
                    detail["fixed_in_version"] = wpvulndb["fixed_in_version"]
                if not detail.get("references") and wpvulndb.get("references"):
                    detail["references"] = wpvulndb["references"]
                if not detail.get("source"):
                    detail["source"] = wpvulndb.get("source", "WPVulnDB")
            if epss:
                detail.update(epss)
            if kev:
                detail["cisa_kev"] = True
                detail["cisa_kev_date_added"] = kev.get("dateAdded")
                detail["cisa_kev_due_date"] = kev.get("dueDate")
                detail["cisa_kev_known_ransomware"] = kev.get("knownRansomwareCampaignUse")
            else:
                detail["cisa_kev"] = False
            cve_details.append(detail)

        if cve_details:
            finding["cve_details"] = cve_details
            epss_scores = [float(item["epss_score"]) for item in cve_details if item.get("epss_score") is not None]
            epss_percentiles = [
                float(item["epss_percentile"])
                for item in cve_details
                if item.get("epss_percentile") is not None
            ]
            if epss_scores:
                finding["epss_score"] = max(epss_scores)
            if epss_percentiles:
                finding["epss_percentile"] = max(epss_percentiles)
            finding["cisa_kev"] = any(bool(item.get("cisa_kev")) for item in cve_details)


def _extract_cves(findings: Iterable[Dict[str, Any]]) -> List[str]:
    cves: List[str] = []
    for finding in findings:
        for cve in finding.get("cve", []) or []:
            if isinstance(cve, str) and cve.startswith("CVE-"):
                cves.append(cve)
    return cves


def _fetch_nvd_metadata(cves: List[str]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}

    # Sorgente offline: corpus locale delle CVE NVD recenti (aggiornato dai feed).
    if getattr(settings, "feed_cache_enabled", False):
        local_index = load_local_nvd_index()
        for cve in cves:
            entry = local_index.get(cve)
            if not entry:
                continue
            results[cve] = {
                "cve": cve,
                "description": entry.get("description", ""),
                "cvss_score": entry.get("cvss_score"),
                "cvss_vector": entry.get("cvss_vector"),
                "fixed_in_version": None,
                "references": [],
                "source": "NVD (cache locale)",
            }

    if not settings.enable_live_scans or not settings.nvd_api_key:
        return results

    for cve in cves[: settings.nvd_max_cves]:
        if cve in results:
            continue  # già risolta dalla cache locale
        try:
            response = requests.get(
                settings.nvd_api_base_url,
                params={"cveId": cve},
                headers={"apiKey": settings.nvd_api_key},
                timeout=settings.nvd_timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException:
            continue

        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        if not vulnerabilities:
            continue
        cve_item = vulnerabilities[0].get("cve", {}) if isinstance(vulnerabilities[0], dict) else {}
        descriptions = cve_item.get("descriptions", []) if isinstance(cve_item, dict) else []
        description = next(
            (desc.get("value") for desc in descriptions if desc.get("lang") == "en"),
            "",
        )

        metrics = cve_item.get("metrics", {}) if isinstance(cve_item, dict) else {}
        cvss_score = None
        cvss_vector = None
        if metrics:
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key)
                if metric_list:
                    metric = metric_list[0]
                    data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
                    cvss_score = data.get("baseScore")
                    cvss_vector = data.get("vectorString")
                    break

        results[cve] = {
            "cve": cve,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "fixed_in_version": _extract_fixed_in_version(cve_item),
            "references": _extract_nvd_references(cve_item),
            "source": "NVD",
        }
    return results


def _fetch_wpvulndb_metadata(cves: List[str]) -> Dict[str, Dict[str, Any]]:
    if not settings.enable_live_scans or not cves:
        return {}

    wpscan_token = getattr(settings, "wpscan_api_token", "")
    if not wpscan_token:
        return {}

    api_base_url = str(getattr(settings, "wpscan_api_base_url", "https://wpscan.com/api/v3")).rstrip("/")
    results: Dict[str, Dict[str, Any]] = {}
    headers = {"Authorization": f"Token token={wpscan_token}"}

    for cve in cves:
        cve_key = str(cve).strip().lower()
        if not cve_key:
            continue
        try:
            response = requests.get(
                f"{api_base_url}/vulnerabilities/{cve_key}",
                headers=headers,
                timeout=settings.nvd_timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException:
            continue

        payload = response.json()
        fixed_in_version = _extract_wpvulndb_fixed_in(payload)
        references = _extract_wpvulndb_references(payload)
        if not fixed_in_version and not references:
            continue

        results[cve] = {
            "fixed_in_version": fixed_in_version,
            "references": references,
            "source": "WPVulnDB",
        }
    return results


def _extract_fixed_in_version(cve_item: Dict[str, Any]) -> Optional[str]:
    configurations = cve_item.get("configurations", []) if isinstance(cve_item, dict) else []
    for config in configurations:
        nodes = config.get("nodes", []) if isinstance(config, dict) else []
        for node in nodes:
            cpe_matches = node.get("cpeMatch", []) if isinstance(node, dict) else []
            for match in cpe_matches:
                if not isinstance(match, dict):
                    continue
                if match.get("versionEndExcluding"):
                    return str(match["versionEndExcluding"])
                if match.get("versionEndIncluding"):
                    return str(match["versionEndIncluding"])
    return None


def _extract_wpvulndb_fixed_in(payload: Any) -> Optional[str]:
    if isinstance(payload, dict):
        for key in ("fixed_in", "fixed_in_version", "patched_in", "patched_version"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for value in payload.values():
            fixed = _extract_wpvulndb_fixed_in(value)
            if fixed:
                return fixed
    elif isinstance(payload, list):
        for item in payload:
            fixed = _extract_wpvulndb_fixed_in(item)
            if fixed:
                return fixed
    return None


def _extract_wpvulndb_references(payload: Any) -> List[str]:
    urls: List[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_lc = str(key).lower()
            if key_lc in {"url", "urls"} and isinstance(value, str) and value.strip():
                urls.append(value.strip())
            elif key_lc in {"url", "urls"} and isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        urls.append(item.strip())
            elif key_lc in {"references", "reference"}:
                urls.extend(_extract_wpvulndb_references(value))
            elif isinstance(value, (dict, list)):
                urls.extend(_extract_wpvulndb_references(value))
    elif isinstance(payload, list):
        for item in payload:
            urls.extend(_extract_wpvulndb_references(item))

    return sorted({url for url in urls if url})


def _extract_nvd_references(cve_item: Dict[str, Any]) -> List[str]:
    references = cve_item.get("references", []) if isinstance(cve_item, dict) else []
    urls: List[str] = []
    for ref in references:
        if isinstance(ref, dict) and ref.get("url"):
            urls.append(str(ref["url"]))
    return urls


def _fetch_epss_metadata(cves: List[str]) -> Dict[str, Dict[str, Any]]:
    if not settings.enable_live_scans or not cves:
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    for cve in cves:
        try:
            response = requests.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": cve},
                timeout=settings.nvd_timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException:
            continue

        payload = response.json()
        entries = payload.get("data", []) if isinstance(payload, dict) else []
        if not entries:
            continue
        item = entries[0]
        if not isinstance(item, dict):
            continue
        try:
            epss_score = float(item.get("epss")) if item.get("epss") is not None else None
        except (TypeError, ValueError):
            epss_score = None
        try:
            percentile = float(item.get("percentile")) if item.get("percentile") is not None else None
        except (TypeError, ValueError):
            percentile = None
        results[cve] = {
            "epss_score": epss_score,
            "epss_percentile": percentile,
            "epss_date": item.get("date"),
        }
    return results


def _fetch_cisa_kev_catalog() -> Dict[str, Dict[str, Any]]:
    # Sorgente offline preferita: catalogo KEV completo dalla cache locale.
    if getattr(settings, "feed_cache_enabled", False):
        local = load_local_kev_catalog()
        if local:
            return local

    if not settings.enable_live_scans:
        return {}

    try:
        response = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=settings.nvd_timeout_seconds,
        )
        response.raise_for_status()
    except requests.RequestException:
        return {}

    payload = response.json()
    results: Dict[str, Dict[str, Any]] = {}
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID", "")).strip()
        if cve_id:
            results[cve_id] = item
    return results


def _fetch_exploitdb_metadata(cves: List[str]) -> Dict[str, Dict[str, Any]]:
    if not settings.enable_live_scans:
        return {}
    if not shutil.which(settings.exploitdb_searchsploit_path):
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    for cve in cves[: settings.exploitdb_max_cves]:
        try:
            completed = subprocess.run(
                [settings.exploitdb_searchsploit_path, "--cve", cve, "-j"],
                capture_output=True,
                text=True,
                timeout=settings.exploitdb_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue

        if completed.returncode != 0:
            continue

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            continue

        results_list = payload.get("RESULTS_EXPLOIT", []) if isinstance(payload, dict) else []
        if not results_list:
            continue
        results[cve] = {
            "cve": cve,
            "exploits": results_list,
            "source": "ExploitDB",
        }
    return results


def _apply_mitre_mapping(findings: List[Dict[str, Any]]) -> None:
    for finding in findings:
        techniques = []
        cwe_list = [str(cwe).upper() for cwe in finding.get("cwe", []) if cwe]
        for cwe in cwe_list:
            techniques.extend(MITRE_CWE_MAPPING.get(cwe, []))

        title = str(finding.get("title", ""))
        description = str(finding.get("description", ""))
        for pattern, technique in KEYWORD_MITRE_MAPPING:
            if pattern.search(title) or pattern.search(description):
                techniques.append(technique)

        if techniques:
            unique = {(tech["technique_id"], tech["technique_name"]): tech for tech in techniques}
            finding["mitre_attack"] = list(unique.values())


def _apply_owasp_mapping(findings: List[Dict[str, Any]]) -> None:
    for finding in findings:
        if finding.get("owasp_2017") and finding.get("owasp_2021") and finding.get("owasp_2025"):
            continue
        cwe_list = [str(cwe).upper() for cwe in finding.get("cwe", []) if cwe]
        for cwe in cwe_list:
            if not finding.get("owasp_2017") and OWASP_2017_MAPPING.get(cwe):
                finding["owasp_2017"] = OWASP_2017_MAPPING[cwe]
            if not finding.get("owasp_2021") and OWASP_2021_MAPPING.get(cwe):
                finding["owasp_2021"] = OWASP_2021_MAPPING[cwe]
            if not finding.get("owasp_2025") and OWASP_2025_MAPPING.get(cwe):
                finding["owasp_2025"] = OWASP_2025_MAPPING[cwe]
            if (
                finding.get("owasp_2017")
                and finding.get("owasp_2021")
                and finding.get("owasp_2025")
            ):
                break


def _apply_false_positive_model(findings: List[Dict[str, Any]]) -> None:
    model = FalsePositiveModel()
    for finding in findings:
        features = build_features(finding)
        score = model.predict_proba(features)
        label = "basso" if score < settings.false_positive_medium_threshold else "medio"
        if score >= settings.false_positive_high_threshold:
            label = "alto"

        finding["false_positive_score"] = round(score, 2)
        finding["false_positive_label"] = label
        finding["confidence"] = round(1 - score, 2)
        finding["false_positive_model"] = {
            "version": model.version,
            "top_factors": model.top_factors(features),
        }


def _apply_correlation(findings: List[Dict[str, Any]]) -> None:
    groups: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        key = _correlation_key(finding)
        if key not in groups:
            groups[key] = {
                "id": hashlib.sha256(key.encode("utf-8")).hexdigest()[:8],
                "tools": set(),
                "count": 0,
            }
        groups[key]["count"] += 1
        tool = finding.get("tool")
        if tool:
            groups[key]["tools"].add(tool)

    for finding in findings:
        key = _correlation_key(finding)
        group = groups[key]
        finding["correlation_id"] = group["id"]
        finding["related_findings"] = group["count"]
        finding["related_tools"] = sorted(group["tools"])


def _correlation_key(finding: Dict[str, Any]) -> str:
    title = str(finding.get("title", "")).strip().lower()
    host = str(finding.get("host", "")).strip().lower()
    path = str(finding.get("path", "")).strip().lower()
    cves = ",".join(sorted([str(cve) for cve in finding.get("cve", []) if cve]))
    cwes = ",".join(sorted([str(cwe) for cwe in finding.get("cwe", []) if cwe]))
    return f"{title}|{host}|{path}|{cves}|{cwes}"
