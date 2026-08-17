from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class PortResult:
    port: int
    service: str
    latency_ms: float | None = None


@dataclass(slots=True)
class HostResult:
    ip: str
    hostname: str | None = None
    ports: list[PortResult] = field(default_factory=list)


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
