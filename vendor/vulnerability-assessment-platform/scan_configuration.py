from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Literal, Optional, Set

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SeverityThreshold = Literal["low", "medium", "high", "critical"]
EvidenceMinimum = Literal["minimal", "standard", "strict"]
AuthMode = Literal["none", "basic", "bearer", "cookie"]


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_hosts: List[str] = Field(default_factory=list, max_length=50)
    in_scope_paths: List[str] = Field(default_factory=list, max_length=100)

    @field_validator("allowed_hosts", "in_scope_paths")
    @classmethod
    def _strip_values(cls, values: List[str]) -> List[str]:
        normalized = [value.strip() for value in values if value and value.strip()]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Sono presenti valori duplicati nel perimetro di scansione.")
        return normalized


class RateAndTimeoutConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests_per_minute: int = Field(60, ge=1, le=600)
    max_concurrency: int = Field(4, ge=1, le=20)
    request_timeout_seconds: int = Field(15, ge=1, le=120)


class CrawlerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(True)
    max_depth: int = Field(2, ge=0, le=10)
    follow_subdomains: bool = Field(False)


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: AuthMode = Field("none")
    username: Optional[str] = Field(None, max_length=128)
    password: Optional[str] = Field(None, max_length=256)
    bearer_token: Optional[str] = Field(None, max_length=4096)
    cookie_header: Optional[str] = Field(None, max_length=4096)

    @model_validator(mode="after")
    def _validate_auth_payload(self) -> "AuthConfig":
        if self.mode == "none":
            return self
        if self.mode == "basic" and (not self.username or not self.password):
            raise ValueError("Per auth basic sono richiesti username e password.")
        if self.mode == "bearer" and not self.bearer_token:
            raise ValueError("Per auth bearer è richiesto bearer_token.")
        if self.mode == "cookie" and not self.cookie_header:
            raise ValueError("Per auth cookie è richiesto cookie_header.")
        return self


class ToolOverrideConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(True)
    timeout_seconds: int = Field(20, ge=1, le=300)
    max_payloads: int = Field(30, ge=1, le=500)


class ScanConfigurationV1(BaseModel):
    """Schema versionato della configurazione scansione (A1)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["scan-config/v1"] = Field("scan-config/v1")
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    runtime: RateAndTimeoutConfig = Field(default_factory=RateAndTimeoutConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    exclusions: List[str] = Field(default_factory=list, max_length=100)
    severity_threshold: SeverityThreshold = Field("low")
    minimum_evidence: EvidenceMinimum = Field("standard")
    tool_overrides: Dict[str, ToolOverrideConfig] = Field(default_factory=dict)
    high_risk_acknowledged: bool = Field(False)
    admin_approval_reference: Optional[str] = Field(None, max_length=64)
    policy_override_requested: bool = Field(False)
    policy_override_reason: Optional[str] = Field(None, max_length=500)

    @field_validator("exclusions")
    @classmethod
    def _validate_exclusions(cls, values: List[str]) -> List[str]:
        normalized = [value.strip() for value in values if value and value.strip()]
        if any(len(value) > 200 for value in normalized):
            raise ValueError("Ogni esclusione deve avere massimo 200 caratteri.")
        return normalized

    @model_validator(mode="after")
    def _validate_policy_override(self) -> "ScanConfigurationV1":
        reason = self.policy_override_reason.strip() if self.policy_override_reason else None
        approval_reference = (
            self.admin_approval_reference.strip().upper() if self.admin_approval_reference else None
        )
        if self.policy_override_requested and not reason:
            raise ValueError("Inserire una motivazione quando richiedi override della policy.")
        if not self.policy_override_requested and reason:
            raise ValueError("policy_override_reason è ammesso solo se policy_override_requested=true.")
        if approval_reference and not approval_reference.startswith("APR-"):
            raise ValueError("admin_approval_reference deve iniziare con 'APR-'.")
        if approval_reference and len(approval_reference) < 8:
            raise ValueError("admin_approval_reference non valido.")
        self.admin_approval_reference = approval_reference
        self.policy_override_reason = reason
        return self


class ScanConfigurationPolicyError(ValueError):
    """Errore di policy durante la validazione della configurazione scansione."""


HIGH_RISK_TOOLS: Set[str] = {"sqlmap", "commix", "nosqlmap"}
RESTRICTED_ROLES_FOR_HIGH_RISK: Set[str] = {"admin"}
MUTUALLY_EXCLUSIVE_TOOLS: Set[frozenset[str]] = {
    frozenset({"zap", "burp"}),
}
SCAN_TYPE_ALLOWED_TOOLS: Dict[str, Set[str]] = {
    "light": {"whatweb", "nikto", "nmap", "httpx", "nikto_headers", "nmap_top_ports"},
    "wordpress": {"wpscan", "whatweb", "nikto", "nuclei", "nmap", "wafw00f", "nuclei_wordpress"},
}


def validate_scan_configuration_policy_v1(
    config: ScanConfigurationV1,
    *,
    scan_type: str,
    actor_role: str,
) -> None:
    """Applica regole server-side di compatibilità e autorizzazione."""

    normalized_scan_type = scan_type.strip().lower()
    normalized_role = actor_role.strip().lower()
    enabled_tools = {
        tool_name.strip().lower()
        for tool_name, override in config.tool_overrides.items()
        if override.enabled
    }

    if not config.crawler.enabled and config.crawler.max_depth > 0:
        raise ScanConfigurationPolicyError(
            "Crawler disabilitato: impostare max_depth=0 oppure abilitare crawler.enabled."
        )

    disallowed_for_scan_type = enabled_tools - SCAN_TYPE_ALLOWED_TOOLS.get(normalized_scan_type, enabled_tools)
    if disallowed_for_scan_type:
        blocked = ", ".join(sorted(disallowed_for_scan_type))
        raise ScanConfigurationPolicyError(
            f"I tool [{blocked}] non sono compatibili con scan_type='{normalized_scan_type}'."
        )

    for tool_pair in MUTUALLY_EXCLUSIVE_TOOLS:
        if tool_pair.issubset(enabled_tools):
            left, right = sorted(tool_pair)
            raise ScanConfigurationPolicyError(
                f"I tool '{left}' e '{right}' non possono essere abilitati insieme."
            )

    restricted_tools = enabled_tools & HIGH_RISK_TOOLS
    if restricted_tools and not config.high_risk_acknowledged:
        raise ScanConfigurationPolicyError(
            "Conferma obbligatoria: abilita high_risk_acknowledged prima di eseguire tool ad alto rischio."
        )
    if (
        restricted_tools
        and normalized_role not in RESTRICTED_ROLES_FOR_HIGH_RISK
        and not config.admin_approval_reference
    ):
        raise ScanConfigurationPolicyError(
            "Per ruoli non admin è richiesto un riferimento di approvazione amministrativa (admin_approval_reference)."
        )


def get_scan_config_schema_v1() -> Dict[str, object]:
    return ScanConfigurationV1.model_json_schema()


def checksum_scan_config_v1(config: ScanConfigurationV1) -> str:
    payload = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _mask_secret(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return "********"


def redact_scan_configuration_secrets(config: ScanConfigurationV1) -> ScanConfigurationV1:
    """Restituisce una copia della configurazione con segreti auth mascherati per output UI/API."""

    redacted = config.model_copy(deep=True)
    redacted.auth.password = _mask_secret(redacted.auth.password)
    redacted.auth.bearer_token = _mask_secret(redacted.auth.bearer_token)
    redacted.auth.cookie_header = _mask_secret(redacted.auth.cookie_header)
    return redacted
