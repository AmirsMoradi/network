from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database.models import DeviceORM, FindingORM, HostORM, PortORM, ScanORM
from app.database.session import Database
from app.domain.models import (
    DeviceObservation,
    ExposureFinding,
    HostResult,
    PortResult,
    RiskLevel,
    ScanDiff,
    ScanResult,
    ServiceFingerprint,
)


class HistoryService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def save_scan(self, result: ScanResult) -> int:
        scan = ScanORM(
            target=result.target,
            started_at=result.started_at,
            completed_at=result.completed_at,
        )
        for host in result.hosts:
            host_orm = HostORM(
                ip=host.ip,
                hostname=host.hostname,
                mac_address=host.mac_address,
                vendor=host.vendor,
                discovery_methods=",".join(host.discovery_methods) or None,
            )
            for port in host.ports:
                fingerprint = port.fingerprint
                port_orm = PortORM(
                    port=port.port,
                    service=port.service,
                    latency_ms=str(port.latency_ms) if port.latency_ms is not None else None,
                    product=fingerprint.product,
                    version=fingerprint.version,
                    banner=fingerprint.banner,
                    tls_version=fingerprint.tls_version,
                    tls_cipher=fingerprint.tls_cipher,
                    certificate_expires_at=fingerprint.certificate_expires_at,
                    certificate_subject=fingerprint.certificate_subject,
                    risk_score=port.risk_score,
                    risk_level=port.risk_level.value,
                )
                for finding in port.findings:
                    port_orm.findings.append(
                        FindingORM(
                            finding_type=finding.finding_type,
                            title=finding.title,
                            severity=finding.severity.value,
                            score=finding.score,
                            evidence=finding.evidence,
                            recommendation=finding.recommendation,
                            cve_id=finding.cve_id,
                            known_exploited=finding.known_exploited,
                        )
                    )
                host_orm.ports.append(port_orm)
            scan.hosts.append(host_orm)

        with self._database.session() as session:
            session.add(scan)
            session.commit()
            return scan.id

    def save_discovery(self, observations: list[DeviceObservation]) -> None:
        now = datetime.now(timezone.utc)
        with self._database.session() as session:
            for item in observations:
                identity = item.mac_address or item.ip
                device = session.scalar(select(DeviceORM).where(DeviceORM.identity_key == identity))
                if device is None and item.mac_address:
                    device = session.scalar(
                        select(DeviceORM).where(
                            DeviceORM.ip == item.ip,
                            DeviceORM.mac_address.is_(None),
                        )
                    )
                    if device is not None:
                        device.identity_key = identity
                if device is None:
                    device = DeviceORM(
                        identity_key=identity,
                        first_seen_at=now,
                        last_seen_at=now,
                        ip=item.ip,
                    )
                    session.add(device)
                device.last_seen_at = now
                device.ip = item.ip
                device.hostname = item.hostname
                device.mac_address = item.mac_address
                device.vendor = item.vendor
                device.discovery_methods = ",".join(item.methods) or None
            session.commit()

    def list_devices(self, limit: int = 500) -> list[DeviceORM]:
        statement = select(DeviceORM).order_by(DeviceORM.last_seen_at.desc()).limit(limit)
        with self._database.session() as session:
            return list(session.scalars(statement).all())

    def list_recent(self, limit: int = 100) -> list[ScanORM]:
        statement = (
            select(ScanORM)
            .options(
                selectinload(ScanORM.hosts)
                .selectinload(HostORM.ports)
                .selectinload(PortORM.findings)
            )
            .order_by(ScanORM.id.desc())
            .limit(limit)
        )
        with self._database.session() as session:
            return list(session.scalars(statement).all())

    def get_scan(self, scan_id: int) -> ScanResult | None:
        statement = (
            select(ScanORM)
            .where(ScanORM.id == scan_id)
            .options(
                selectinload(ScanORM.hosts)
                .selectinload(HostORM.ports)
                .selectinload(PortORM.findings)
            )
        )
        with self._database.session() as session:
            scan = session.scalar(statement)
            if scan is None:
                return None
            return self._to_domain(scan)

    def compare_scans(self, older_scan_id: int, newer_scan_id: int) -> ScanDiff:
        older = self.get_scan(older_scan_id)
        newer = self.get_scan(newer_scan_id)
        if older is None or newer is None:
            raise ValueError("One or both scans do not exist")

        old_hosts = {host.ip: host for host in older.hosts}
        new_hosts = {host.ip: host for host in newer.hosts}
        new_host_ips = tuple(sorted(set(new_hosts) - set(old_hosts)))
        removed_host_ips = tuple(sorted(set(old_hosts) - set(new_hosts)))

        new_ports: list[str] = []
        closed_ports: list[str] = []
        changed_services: list[str] = []
        for ip in sorted(set(old_hosts) & set(new_hosts)):
            old_map = {port.port: port for port in old_hosts[ip].ports}
            new_map = {port.port: port for port in new_hosts[ip].ports}
            for port in sorted(set(new_map) - set(old_map)):
                new_ports.append(f"{ip}:{port}/{new_map[port].service}")
            for port in sorted(set(old_map) - set(new_map)):
                closed_ports.append(f"{ip}:{port}/{old_map[port].service}")
            for port in sorted(set(old_map) & set(new_map)):
                old_signature = (
                    old_map[port].service,
                    old_map[port].fingerprint.product,
                    old_map[port].fingerprint.version,
                )
                new_signature = (
                    new_map[port].service,
                    new_map[port].fingerprint.product,
                    new_map[port].fingerprint.version,
                )
                if old_signature != new_signature:
                    changed_services.append(f"{ip}:{port} {old_signature} -> {new_signature}")

        return ScanDiff(
            older_scan_id=older_scan_id,
            newer_scan_id=newer_scan_id,
            new_hosts=new_host_ips,
            removed_hosts=removed_host_ips,
            new_ports=tuple(new_ports),
            closed_ports=tuple(closed_ports),
            changed_services=tuple(changed_services),
        )

    @staticmethod
    def _to_domain(scan: ScanORM) -> ScanResult:
        hosts: list[HostResult] = []
        for host in scan.hosts:
            ports: list[PortResult] = []
            for port in host.ports:
                findings = tuple(
                    ExposureFinding(
                        finding_type=finding.finding_type,
                        title=finding.title,
                        severity=RiskLevel(finding.severity),
                        score=finding.score,
                        ip=host.ip,
                        port=port.port,
                        evidence=finding.evidence,
                        recommendation=finding.recommendation,
                        cve_id=finding.cve_id,
                        known_exploited=finding.known_exploited,
                    )
                    for finding in port.findings
                )
                ports.append(
                    PortResult(
                        port=port.port,
                        service=port.service,
                        latency_ms=float(port.latency_ms) if port.latency_ms else None,
                        fingerprint=ServiceFingerprint(
                            product=port.product,
                            version=port.version,
                            banner=port.banner,
                            tls_version=port.tls_version,
                            tls_cipher=port.tls_cipher,
                            certificate_expires_at=port.certificate_expires_at,
                            certificate_subject=port.certificate_subject,
                        ),
                        risk_score=port.risk_score or 0,
                        risk_level=RiskLevel(port.risk_level or "low"),
                        findings=findings,
                    )
                )
            hosts.append(
                HostResult(
                    ip=host.ip,
                    hostname=host.hostname,
                    mac_address=host.mac_address,
                    vendor=host.vendor,
                    discovery_methods=tuple((host.discovery_methods or "").split(","))
                    if host.discovery_methods
                    else (),
                    ports=ports,
                )
            )
        return ScanResult(
            target=scan.target,
            hosts=hosts,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
        )
