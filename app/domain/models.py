from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DeviceTrust(StrEnum):
    UNKNOWN = "unknown"
    TRUSTED = "trusted"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class ServiceFingerprint:
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    certificate_expires_at: datetime | None = None
    certificate_subject: str | None = None


@dataclass(frozen=True, slots=True)
class ExposureFinding:
    finding_type: str
    title: str
    severity: RiskLevel
    score: int
    ip: str
    port: int | None
    evidence: str
    recommendation: str
    cve_id: str | None = None
    known_exploited: bool = False


@dataclass(frozen=True, slots=True)
class PortResult:
    port: int
    service: str
    latency_ms: float | None = None
    fingerprint: ServiceFingerprint = field(default_factory=ServiceFingerprint)
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    findings: tuple[ExposureFinding, ...] = ()


@dataclass(slots=True)
class HostResult:
    ip: str
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    discovery_methods: tuple[str, ...] = ()
    ports: list[PortResult] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DeviceObservation:
    ip: str
    hostname: str | None
    mac_address: str | None
    vendor: str | None
    methods: tuple[str, ...]
    latency_ms: float | None


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    id: int
    identity_key: str
    first_seen_at: datetime
    last_seen_at: datetime
    ip: str
    hostname: str | None
    mac_address: str | None
    vendor: str | None
    discovery_methods: tuple[str, ...]
    trust_status: DeviceTrust
    custom_name: str | None
    notes: str | None
    is_online: bool
    last_latency_ms: float | None
    last_state_change_at: datetime | None

    @property
    def display_name(self) -> str:
        return self.custom_name or self.hostname or self.ip


@dataclass(frozen=True, slots=True)
class EventRecord:
    id: int
    created_at: datetime
    event_type: str
    severity: RiskLevel
    title: str
    message: str
    device_id: int | None
    device_name: str | None
    ip: str | None


@dataclass(frozen=True, slots=True)
class AlertRecord:
    id: int
    created_at: datetime
    severity: RiskLevel
    category: str
    title: str
    message: str
    device_id: int | None
    device_name: str | None
    ip: str | None
    acknowledged: bool
    acknowledged_at: datetime | None


@dataclass(frozen=True, slots=True)
class MonitorCycleSummary:
    discovered: int
    new_devices: int
    came_online: int
    went_offline: int
    alerts_created: int
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class PingResult:
    host: str
    transmitted: int
    received: int
    packet_loss_percent: float
    average_latency_ms: float | None


@dataclass(frozen=True, slots=True)
class ListenerRecord:
    protocol: str
    local_ip: str
    port: int
    pid: int | None
    process_name: str
    executable: str | None
    username: str | None
    signature_status: str | None
    defender_detected: bool
    risk_score: int
    risk_level: RiskLevel
    risk_reasons: tuple[str, ...]


@dataclass(slots=True)
class ScanResult:
    target: str
    hosts: list[HostResult]
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ScanDiff:
    older_scan_id: int
    newer_scan_id: int
    new_hosts: tuple[str, ...]
    removed_hosts: tuple[str, ...]
    new_ports: tuple[str, ...]
    closed_ports: tuple[str, ...]
    changed_services: tuple[str, ...]
