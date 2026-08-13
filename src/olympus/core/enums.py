"""Shared enumerations used across the whole Olympus data contract."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Normalized severity scale shared by findings, alerts and reports."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """Lifecycle state of a finding inside the remediation workflow."""

    NEW = "new"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    IN_REMEDIATION = "in_remediation"
    CLOSED = "closed"


class Criticality(StrEnum):
    """Business criticality of an asset."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetType(StrEnum):
    """Kind of asset observed or managed by the platform."""

    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    WEB_SERVER = "web_server"
    SERVICE = "service"
    URL = "url"
    OTHER = "other"


class Source(StrEnum):
    """Producing module for a given object (provenance)."""

    ARGUS = "argus"
    HELIOS = "helios"
    ARTEMIS = "artemis"
    PROTEUS = "proteus"
    HERMES = "hermes"
    APOLLO = "apollo"
    MINERVA = "minerva"
    VULCAN = "vulcan"
    MARS = "mars"
    MANUAL = "manual"


class EventType(StrEnum):
    """Broad category of a single observed telemetry event."""

    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    DNS = "dns"
    OTHER = "other"


class EvidenceType(StrEnum):
    """Kind of artifact backing an alert, finding or incident."""

    LOG_EXCERPT = "log_excerpt"
    FILE_HASH = "file_hash"
    SCREENSHOT = "screenshot"
    NETWORK_CAPTURE = "network_capture"
    OTHER = "other"
