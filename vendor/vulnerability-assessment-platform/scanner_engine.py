#!/usr/bin/env python3
"""Scan orchestration engine."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from ipaddress import ip_address, ip_network
import re
import sys
from typing import Any, Dict, List
from urllib.parse import urlparse

import bleach
import requests
import validators

from config import settings
from enrichment_engine import enrich_findings
from scanners import (
    NucleiScanner,
    NmapScanner,
    WhatWebScanner,
    SubfinderScanner,
    NiktoScanner,
    DirsearchScanner,
    SqlmapScanner,
    XsstrikeScanner,
    ZapScanner,
    BurpScanner,
    WapitiScanner,
    CommixScanner,
    AcunetixScanner,
    NessusScanner,
    OpenVASScanner,
    WpscanScanner,
    Wafw00fScanner,
    TestsslScanner,
    TheHarvesterScanner,
    ArjunScanner,
    DalfoxScanner,
    HttpxScanner,
    KatanaScanner,
    NosqlmapScanner,
)


IPV4_OCTET_REGEX = r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})"
IPV4_ADDRESS_REGEX = rf"{IPV4_OCTET_REGEX}(?:\.{IPV4_OCTET_REGEX}){{3}}"
TARGET_REGEX = re.compile(
    rf"^(https?://)?([a-zA-Z0-9.-]+|{IPV4_ADDRESS_REGEX})(:\d{{1,5}})?(/.*)?$"
)
SCANNER_NAME_REGEX = re.compile(r"^[a-z0-9_]+$")


class WordpressNucleiScanner(NucleiScanner):
    def __init__(self, enable_live_scans: bool):
        super().__init__(enable_live_scans=enable_live_scans, template_profile="wordpress")


class LightNiktoScanner(NiktoScanner):
    """Nikto variant for light profile: keep only HTTP header checks."""

    HEADER_KEYWORDS = (
        "header",
        "headers",
        "csp",
        "hsts",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    )

    def run(self, target: str) -> Dict[str, Any]:
        result = super().run(target)
        findings = result.get("findings")
        if not isinstance(findings, list):
            return result
        result["findings"] = [
            finding for finding in findings if self._is_header_finding(finding)
        ]
        return result

    def _is_header_finding(self, finding: Dict[str, Any]) -> bool:
        payload = " ".join(
            str(finding.get(field, "")).lower()
            for field in ("title", "description", "evidence", "recommendation")
        )
        return any(keyword in payload for keyword in self.HEADER_KEYWORDS)


class LightNmapScanner(NmapScanner):
    """Nmap variant for light profile: always top ports."""

    def _profile_args(self, _profile: str) -> List[str]:
        return super()._profile_args("quick")


class NetworkNmapScanner(NmapScanner):
    """Nmap variant for the network profile: service detection + NSE vuln scripts.

    Esegue rilevamento servizio/versione e gli script NSE ``vulners`` e ``vuln``
    che, a partire da prodotto/versione, individuano CVE note. Le CVE rilevate
    confluiscono nell'enrichment (CVSS/CISA KEV/EPSS) dai feed ufficiali.
    """

    def _profile_args(self, _profile: str) -> List[str]:
        return super()._profile_args("service")

    def _script_args(self) -> List[str]:
        return ["--script", "vulners,vuln"]


SCANNERS_MAP = {
    "nuclei": NucleiScanner,
    "nmap": NmapScanner,
    "whatweb": WhatWebScanner,
    "subfinder": SubfinderScanner,
    "nikto": NiktoScanner,
    "dirsearch": DirsearchScanner,
    "sqlmap": SqlmapScanner,
    "xsstrike": XsstrikeScanner,
    "zap": ZapScanner,
    "burp": BurpScanner,
    "wapiti": WapitiScanner,
    "commix": CommixScanner,
    "acunetix": AcunetixScanner,
    "nessus": NessusScanner,
    "openvas": OpenVASScanner,
    "wpscan": WpscanScanner,
    "wafw00f": Wafw00fScanner,
    "testssl": TestsslScanner,
    "theharvester": TheHarvesterScanner,
    "arjun": ArjunScanner,
    "dalfox": DalfoxScanner,
    "httpx": HttpxScanner,
    "katana": KatanaScanner,
    "nosqlmap": NosqlmapScanner,
}
TOOL_DISPLAY_NAMES = {
    "nuclei": "Nuclei",
    "nmap": "Nmap",
    "whatweb": "WhatWeb",
    "subfinder": "Subfinder",
    "nikto": "Nikto",
    "dirsearch": "Dirsearch",
    "sqlmap": "SQLMap",
    "xsstrike": "XSStrike",
    "zap": "OWASP ZAP",
    "burp": "Burp Scanner",
    "wapiti": "Wapiti",
    "commix": "Commix",
    "acunetix": "Acunetix",
    "nessus": "Nessus",
    "openvas": "OpenVAS / Greenbone",
    "arjun": "Arjun",
    "dalfox": "Dalfox",
    "katana": "Katana",
    "wpscan": "WPScan",
    "wafw00f": "wafw00f",
    "testssl": "testssl.sh",
    "theharvester": "theHarvester",
    "httpx": "httpx",
    "nosqlmap": "NoSQLMap",
    "nuclei_wordpress": "Nuclei (WordPress)",
    "nikto_headers": "Nikto (security headers)",
    "nmap_top_ports": "Nmap (top ports)",
    "nmap_network": "Nmap (rete + CVE)",
}
PROFILE_SCANNERS_MAP = {
    "nuclei_wordpress": WordpressNucleiScanner,
    "nikto_headers": LightNiktoScanner,
    "nmap_top_ports": LightNmapScanner,
    "nmap_network": NetworkNmapScanner,
}
SCAN_TYPE_PROFILES = {
    "light": ["whatweb", "nikto_headers", "nmap_top_ports", "httpx"],
    "wordpress": ["wpscan", "whatweb", "nikto", "nuclei_wordpress", "nmap", "wafw00f"],
    "network": ["nmap_network", "testssl"],
}
PLUGIN_CONTRACT_VERSION = "1.0.0"


def get_scan_type_choices() -> List[str]:
    """Restituisce i tipi di scansione validi allineati a mappe scanner/profili."""
    ordered_choices = ["full", *SCAN_TYPE_PROFILES.keys(), *SCANNERS_MAP.keys()]
    deduped_choices: List[str] = []
    for scan_type in ordered_choices:
        if scan_type not in deduped_choices:
            deduped_choices.append(scan_type)
    return deduped_choices


SCAN_TYPE_CHOICES = get_scan_type_choices()


@dataclass
class ScannerPluginSpec:
    scanner_name: str
    scanner_class: type
    display_name: str | None = None
    profile_assignments: List[str] = field(default_factory=list)
    contract_version: str = PLUGIN_CONTRACT_VERSION


def _validate_plugin_contract_version(contract_version: str) -> None:
    if contract_version != PLUGIN_CONTRACT_VERSION:
        raise ScanValidationError(
            "Scanner plugin contract non supportato. "
            f"Versione richiesta: {PLUGIN_CONTRACT_VERSION}, ricevuta: {contract_version}."
        )


def _validate_plugin_name(scanner_name: str) -> str:
    normalized_name = scanner_name.lower().strip()
    if not SCANNER_NAME_REGEX.fullmatch(normalized_name):
        raise ScanValidationError(
            "Nome scanner plugin non valido: usare solo caratteri [a-z0-9_]."
        )
    if normalized_name in {"full", *SCAN_TYPE_PROFILES.keys()}:
        raise ScanValidationError(
            "Nome scanner plugin riservato: conflitto con scan type di sistema."
        )
    return normalized_name


def register_scanner_plugin(spec: ScannerPluginSpec) -> None:
    """Registra scanner esterni secondo contratto versionato.

    Il contratto è intenzionalmente fail-closed: se il plugin non rispetta naming,
    versione o profili supportati, viene rifiutato.
    """
    _validate_plugin_contract_version(spec.contract_version)
    scanner_name = _validate_plugin_name(spec.scanner_name)

    if not callable(spec.scanner_class):
        raise ScanValidationError("scanner_class plugin non valido: oggetto non istanziabile.")
    if scanner_name in SCANNERS_MAP:
        raise ScanValidationError(f"Scanner plugin '{scanner_name}' già registrato.")

    normalized_profiles: List[str] = []
    for profile_name in spec.profile_assignments:
        normalized_profile = profile_name.lower().strip()
        if normalized_profile not in SCAN_TYPE_PROFILES:
            raise ScanValidationError(
                f"Profilo plugin non riconosciuto: '{profile_name}'. "
                f"Profili supportati: {', '.join(sorted(SCAN_TYPE_PROFILES.keys()))}."
            )
        normalized_profiles.append(normalized_profile)

    SCANNERS_MAP[scanner_name] = spec.scanner_class
    if spec.display_name:
        TOOL_DISPLAY_NAMES[scanner_name] = spec.display_name

    for normalized_profile in normalized_profiles:
        if scanner_name not in SCAN_TYPE_PROFILES[normalized_profile]:
            SCAN_TYPE_PROFILES[normalized_profile].append(scanner_name)

    global SCAN_TYPE_CHOICES
    SCAN_TYPE_CHOICES = get_scan_type_choices()

@dataclass
class ScanResult:
    target: str
    scan_type: str
    status: str
    started_at: datetime
    completed_at: datetime
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class ScanValidationError(ValueError):
    pass


def _normalize_allowlist_entry(entry: str) -> str:
    normalized = entry.strip().lower()
    if normalized.startswith("*."):
        return normalized[2:]
    return normalized


def _is_hostname_allowed(hostname: str) -> bool:
    if settings.app_env != "production" or not settings.target_allowlist:
        return True

    candidate = hostname.strip().lower()
    for raw_entry in settings.target_allowlist:
        entry = _normalize_allowlist_entry(raw_entry)
        if not entry or "/" in entry:
            continue
        if candidate == entry or candidate.endswith(f".{entry}"):
            return True
    return False


def _is_ip_allowed(value: str) -> bool:
    if settings.app_env != "production" or not settings.target_allowlist:
        return True

    try:
        candidate_ip = ip_address(value)
    except ValueError:
        return False

    for raw_entry in settings.target_allowlist:
        entry = _normalize_allowlist_entry(raw_entry)
        if not entry:
            continue
        if "/" in entry:
            try:
                if candidate_ip in ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
            continue
        if re.fullmatch(r"\d+(?:\.\d+){3}", entry):
            try:
                if candidate_ip == ip_address(entry):
                    return True
            except ValueError:
                continue
    return False


def _assert_target_in_allowlist(target_value: str) -> None:
    if settings.app_env != "production" or not settings.target_allowlist:
        return

    if re.fullmatch(r"\d+(?:\.\d+){3}", target_value):
        is_allowed = _is_ip_allowed(target_value)
    else:
        is_allowed = _is_hostname_allowed(target_value)

    if not is_allowed:
        raise ScanValidationError(
            "Target non consentito dalla allowlist di produzione. "
            "Configura VAP_TARGET_ALLOWLIST per autorizzarlo."
        )


def _assert_network_target_in_allowlist(target_value: str) -> None:
    try:
        candidate_network = ip_network(target_value, strict=False)
    except ValueError as exc:
        raise ScanValidationError("CIDR non valido.") from exc

    if settings.app_env != "production" or not settings.target_allowlist:
        return

    for raw_entry in settings.target_allowlist:
        entry = _normalize_allowlist_entry(raw_entry)
        if "/" not in entry:
            continue
        try:
            allowed_network = ip_network(entry, strict=False)
        except ValueError:
            continue
        if candidate_network.subnet_of(allowed_network):
            return

    raise ScanValidationError(
        "Target CIDR non consentito dalla allowlist di produzione. "
        "Configura VAP_TARGET_ALLOWLIST per autorizzarlo."
    )


def validate_target(target: str) -> str:
    if not target or len(target) > 255:
        raise ScanValidationError("Target non valido o troppo lungo.")

    target = bleach.clean(target, tags=[], attributes={}, strip=True).strip()
    if not TARGET_REGEX.match(target):
        raise ScanValidationError("Formato target non valido. Usa URL o IP.")

    parsed = urlparse(target if target.startswith("http") else f"http://{target}")
    if not parsed.hostname:
        raise ScanValidationError("Hostname non valido.")
    hostname = parsed.hostname
    if not (validators.domain(hostname) or validators.ipv4(hostname)):
        raise ScanValidationError("Hostname non valido.")
    if re.fullmatch(r"\d+(?:\.\d+){3}", hostname):
        try:
            ip_address(hostname)
        except ValueError as exc:
            raise ScanValidationError("IP non valido.") from exc
    _assert_target_in_allowlist(hostname)

    return target


def detect_target_redirect(target: str) -> Dict[str, str]:
    """Detect HTTP->HTTPS redirect and keep traceability metadata."""
    parsed = urlparse(target if target.startswith("http") else f"http://{target}")
    if not parsed.hostname:
        return {"validated_target": target}

    original_target = target
    normalized_target = target if target.startswith("http") else f"http://{target}"
    redirect_from = ""

    try:
        response = requests.get(
            normalized_target,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "VAP-Redirect-Detector/1.0"},
        )
        final_url = response.url or normalized_target
        if (
            normalized_target.startswith("http://")
            and final_url.startswith("https://")
            and final_url != normalized_target
        ):
            redirect_from = normalized_target
            validated_target = final_url
        else:
            validated_target = original_target
    except requests.RequestException:
        validated_target = original_target

    return {"validated_target": validated_target, "redirect_from": redirect_from}


def validate_nmap_target(target: str) -> str:
    if not target or len(target) > 255:
        raise ScanValidationError("Target non valido o troppo lungo.")

    target = bleach.clean(target, tags=[], attributes={}, strip=True).strip()
    if " " in target:
        raise ScanValidationError("Il target Nmap non deve contenere spazi.")

    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ScanValidationError("Hostname non valido.")
        if not (validators.domain(parsed.hostname) or validators.ipv4(parsed.hostname)):
            raise ScanValidationError("Hostname non valido.")
        if re.fullmatch(r"\d+(?:\.\d+){3}", parsed.hostname):
            try:
                ip_address(parsed.hostname)
            except ValueError as exc:
                raise ScanValidationError("IP non valido.") from exc
        _assert_target_in_allowlist(parsed.hostname)
        return parsed.hostname

    if "/" in target:
        _assert_network_target_in_allowlist(target)
        return target

    if "-" in target:
        start, end = target.split("-", maxsplit=1)
        start = start.strip()
        end = end.strip()
        try:
            start_ip = ip_address(start)
        except ValueError as exc:
            raise ScanValidationError("IP iniziale non valido.") from exc

        if "." not in end:
            start_octets = start.split(".")
            if len(start_octets) != 4:
                raise ScanValidationError("Formato range IP non valido.")
            try:
                end_octet = int(end)
            except ValueError as exc:
                raise ScanValidationError("Ottetto finale range non valido.") from exc
            if not 0 <= end_octet <= 255:
                raise ScanValidationError("Ottetto finale range non valido.")
            end_ip = ip_address(".".join(start_octets[:3] + [str(end_octet)]))
        else:
            try:
                end_ip = ip_address(end)
            except ValueError as exc:
                raise ScanValidationError("IP finale non valido.") from exc

        if int(end_ip) < int(start_ip):
            raise ScanValidationError("Range IP non valido: fine < inizio.")
        return target

    if not TARGET_REGEX.match(target):
        raise ScanValidationError("Formato target non valido. Usa URL o IP.")

    parsed = urlparse(f"http://{target}")
    if not parsed.hostname:
        raise ScanValidationError("Hostname non valido.")
    hostname = parsed.hostname
    if not (validators.domain(hostname) or validators.ipv4(hostname)):
        raise ScanValidationError("Hostname non valido.")
    if re.fullmatch(r"\d+(?:\.\d+){3}", hostname):
        try:
            ip_address(hostname)
        except ValueError as exc:
            raise ScanValidationError("IP non valido.") from exc
    _assert_target_in_allowlist(hostname)

    return target


def _collect_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for result in results:
        tool_name = result.get("tool", "")
        for finding in result.get("findings", []):
            finding = dict(finding)
            _normalize_finding_http_context(finding)
            if tool_name and not finding.get("tool"):
                finding["tool"] = tool_name
            if tool_name:
                display_name = TOOL_DISPLAY_NAMES.get(tool_name.lower(), tool_name.title())
                finding.setdefault("found_by", f"{display_name} – Active Testing")
            else:
                finding.setdefault("found_by", "Active Testing")
            findings.append(finding)
    return findings[: settings.max_findings]


def _normalize_finding_http_context(finding: Dict[str, Any]) -> None:
    method = finding.get("method")
    if isinstance(method, str):
        method = method.strip().upper()
    elif method:
        method = str(method).strip().upper()
    else:
        method = None
    if method:
        finding["method"] = method

    if "parameters" not in finding and finding.get("parameter"):
        finding["parameters"] = [str(finding["parameter"]).strip()]

    parameters = finding.get("parameters")
    normalized_parameters: List[str] = []
    if isinstance(parameters, str):
        normalized_parameters = [param.strip() for param in parameters.split(",") if param.strip()]
    elif isinstance(parameters, list):
        normalized_parameters = [str(param).strip() for param in parameters if str(param).strip()]
    elif isinstance(parameters, dict):
        normalized_parameters = [str(param).strip() for param in parameters.keys() if str(param).strip()]
    elif parameters:
        normalized_parameters = [str(parameters).strip()]

    if normalized_parameters:
        finding["parameters"] = normalized_parameters

    evidence = finding.get("evidence")
    if not isinstance(evidence, str):
        return

    evidence = evidence.strip()
    if not evidence:
        return

    context_parts: List[str] = []
    if method:
        context_parts.append(f"Metodo HTTP: {method}")
    if normalized_parameters:
        context_parts.append(f"Parametri: {', '.join(normalized_parameters)}")
    if not context_parts:
        return

    context_line = " | ".join(context_parts)
    if context_line in evidence:
        return
    finding["evidence"] = f"{context_line}\n{evidence}"


def _measure_target_avg_response_time_ms(target: str, samples: int = 3, timeout: int = 5) -> float | None:
    normalized_target = target if target.startswith(("http://", "https://")) else f"http://{target}"
    durations_ms: List[float] = []

    for _ in range(max(1, samples)):
        try:
            response = requests.get(
                normalized_target,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "VAP-Response-Time-Probe/1.0"},
            )
            durations_ms.append(float(response.elapsed.total_seconds() * 1000))
        except requests.RequestException:
            continue

    if not durations_ms:
        return None
    return round(sum(durations_ms) / len(durations_ms), 2)


def _compute_scan_stats(
    results: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    target: str | None = None,
) -> Dict[str, Any]:
    tests_performed = 0
    urls: set[str] = set()
    urls_spidered_total = 0
    unique_injection_points: set[str] = set()
    http_requests_total = 0
    response_times: List[float] = []

    for result in results:
        result_findings = result.get("findings", [])
        tests_performed += int(result.get("tests_performed") or len(result_findings))
        scanner_urls_spidered = result.get("urls_spidered")
        if isinstance(scanner_urls_spidered, (int, float)) and scanner_urls_spidered >= 0:
            urls_spidered_total += int(scanner_urls_spidered)
        scanner_http_requests = result.get("http_requests_total")
        if scanner_http_requests is None:
            scanner_http_requests = result.get("total_http_requests")
        http_requests_total += int(scanner_http_requests or 0)

        avg_ms = result.get("avg_response_time_ms")
        if isinstance(avg_ms, (int, float)) and avg_ms >= 0:
            response_times.append(float(avg_ms))

    for finding in findings:
        evidence_url = finding.get("evidence_url") or finding.get("url") or finding.get("affected_url")
        if isinstance(evidence_url, str) and evidence_url:
            urls.add(evidence_url)

        method = finding.get("method")
        parameters = finding.get("parameters")
        if method and not isinstance(method, str):
            finding["method"] = str(method)
        if parameters and not isinstance(parameters, (list, dict, str)):
            finding["parameters"] = str(parameters)

        evidence_url = (
            finding.get("evidence_url")
            or finding.get("url")
            or finding.get("affected_url")
            or ""
        )
        normalized_method = str(finding.get("method") or "").upper()
        base_context = f"{evidence_url}|{normalized_method}"

        if isinstance(parameters, list):
            for parameter in parameters:
                normalized_parameter = str(parameter).strip()
                if normalized_parameter:
                    unique_injection_points.add(f"{base_context}|{normalized_parameter}")
        elif isinstance(parameters, dict):
            for parameter in parameters.keys():
                normalized_parameter = str(parameter).strip()
                if normalized_parameter:
                    unique_injection_points.add(f"{base_context}|{normalized_parameter}")
        elif isinstance(parameters, str) and parameters.strip():
            unique_injection_points.add(f"{base_context}|{parameters.strip()}")

    avg_response_time_ms = round(sum(response_times) / len(response_times), 2) if response_times else None
    if avg_response_time_ms is None and target:
        avg_response_time_ms = _measure_target_avg_response_time_ms(target)
    if not http_requests_total:
        http_requests_total = tests_performed

    injection_points = len(unique_injection_points)
    return {
        "tests_performed": tests_performed,
        "urls_spidered": urls_spidered_total or len(urls),
        "injection_points": injection_points,
        "unique_injection_points": injection_points,
        "http_requests_total": http_requests_total,
        "total_http_requests": http_requests_total,
        "avg_response_time_ms": avg_response_time_ms,
    }


def _scanner_label(scanner_cls: type) -> str:
    return scanner_cls.__name__.replace("Scanner", "").lower()


def _run_scanner(scanner_cls: type, target: str) -> Dict[str, Any]:
    scanner = scanner_cls(enable_live_scans=settings.enable_live_scans)
    try:
        result = scanner.run(target)
        if not isinstance(result, dict):
            return {
                "tool": _scanner_label(scanner_cls),
                "status": "error",
                "error_type": "invalid_result",
                "message": "scanner returned invalid payload",
                "findings": [],
                "tests_performed": 0,
            }

        findings = result.get("findings")
        if not isinstance(findings, list):
            findings = []
            result["findings"] = findings

        tests_performed = result.get("tests_performed")
        if not isinstance(tests_performed, int) or tests_performed < 0:
            result["tests_performed"] = len(findings)

        return result
    except TimeoutError as exc:
        return {
            "tool": _scanner_label(scanner_cls),
            "status": "error",
            "error_type": "timeout",
            "message": str(exc),
            "findings": [],
        }
    except ValueError as exc:
        return {
            "tool": _scanner_label(scanner_cls),
            "status": "error",
            "error_type": "validation",
            "message": str(exc),
            "findings": [],
        }
    except Exception:
        return {
            "tool": _scanner_label(scanner_cls),
            "status": "error",
            "error_type": "unexpected",
            "message": "scanner runtime error",
            "findings": [],
        }


def _resolve_scanner_class(scanner_name: str) -> type:
    if scanner_name in SCANNERS_MAP:
        return SCANNERS_MAP[scanner_name]
    if scanner_name in PROFILE_SCANNERS_MAP:
        return PROFILE_SCANNERS_MAP[scanner_name]
    raise ScanValidationError(f"Scanner non supportato nel profilo: {scanner_name}.")


def get_scanner_classes(scan_type: str) -> List[type]:
    scan_type = scan_type.lower().strip()
    if scan_type == "full":
        return list(SCANNERS_MAP.values())
    if scan_type in SCAN_TYPE_PROFILES:
        scanner_names = SCAN_TYPE_PROFILES[scan_type]
        return [_resolve_scanner_class(name) for name in scanner_names]
    if scan_type in SCANNERS_MAP:
        return [SCANNERS_MAP[scan_type]]
    raise ScanValidationError("Tipo di scansione non supportato.")


def run_single_scanner(scanner_name: str, target: str) -> Dict[str, Any]:
    scanner_cls = SCANNERS_MAP.get(scanner_name.lower().strip())
    if not scanner_cls:
        raise ScanValidationError("Scanner non supportato.")
    return _run_scanner(scanner_cls, target)


def run_scan(target: str, scan_type: str) -> ScanResult:
    scan_type = scan_type.lower().strip()
    scanner_classes = get_scanner_classes(scan_type)

    if scan_type == "nmap":
        validated_target = validate_nmap_target(target)
        redirect_from = ""
    else:
        validated_target = validate_target(target)
        redirect_data = detect_target_redirect(validated_target)
        validated_target = redirect_data["validated_target"]
        redirect_from = redirect_data["redirect_from"]

    started_at = datetime.now(timezone.utc)
    results: List[Dict[str, Any]] = []

    max_workers = max(1, min(len(scanner_classes), settings.max_concurrent_scanners))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_run_scanner, scanner_cls, validated_target): scanner_cls
            for scanner_cls in scanner_classes
        }
        for future in as_completed(future_map):
            results.append(future.result())

    findings = _collect_findings(results)
    findings = enrich_findings(findings)
    metadata = _compute_scan_stats(results, findings, target=validated_target)
    metadata["redirect_from"] = redirect_from
    completed_at = datetime.now(timezone.utc)

    return ScanResult(
        target=validated_target,
        scan_type=scan_type,
        status="completed",
        started_at=started_at,
        completed_at=completed_at,
        findings=findings,
        metadata=metadata,
    )


def serialize_findings(findings: List[Dict[str, Any]]) -> str:
    return json.dumps(findings, ensure_ascii=False, indent=2)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Esegui una scansione di sicurezza.")
    parser.add_argument("--target", required=True, help="Target della scansione (URL o IP).")
    parser.add_argument(
        "--scan-type",
        default="full",
        choices=get_scan_type_choices(),
        help="Tipo di scansione da eseguire.",
    )
    parser.add_argument(
        "--output",
        help="Percorso file JSON dove salvare i risultati. Se omesso, stampa su stdout.",
    )
    return parser


def main() -> int:
    parser = _build_cli_parser()
    args = parser.parse_args()

    try:
        scan_result = run_scan(target=args.target, scan_type=args.scan_type)
    except ScanValidationError as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 2

    payload = {
        "target": scan_result.target,
        "scan_type": scan_result.scan_type,
        "status": scan_result.status,
        "started_at": scan_result.started_at.isoformat(),
        "completed_at": scan_result.completed_at.isoformat(),
        "findings": scan_result.findings,
        "metadata": scan_result.metadata,
    }
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as outfile:
            outfile.write(serialized)
    else:
        print(serialized)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
