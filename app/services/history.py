from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session, selectinload

from app.database.models import (
    AlertORM,
    DeviceORM,
    EventORM,
    FindingORM,
    HostORM,
    PortORM,
    ScanORM,
)
from app.database.session import Database
from app.domain.models import (
    AlertRecord,
    DeviceObservation,
    DeviceRecord,
    DeviceTrust,
    EventRecord,
    ExposureFinding,
    HostResult,
    MonitorCycleSummary,
    PortResult,
    RiskLevel,
    ScanDiff,
    ScanResult,
    ServiceFingerprint,
)


class HistoryService:
    def __init__(self, database: Database) -> None:
        self._database = database

    # ------------------------------------------------------------------
    # Network assessment history
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Persistent device inventory and presence monitoring
    # ------------------------------------------------------------------
    def save_discovery(self, observations: list[DeviceObservation]) -> MonitorCycleSummary:
        """Persist a manual discovery without marking unobserved devices offline."""
        return self._record_presence(observations, target=None, mark_missing_offline=False)

    def record_monitor_cycle(
        self,
        observations: list[DeviceObservation],
        target: str,
    ) -> MonitorCycleSummary:
        """Persist one monitor cycle and derive online/offline transitions."""
        return self._record_presence(observations, target=target, mark_missing_offline=True)

    def _record_presence(
        self,
        observations: list[DeviceObservation],
        *,
        target: str | None,
        mark_missing_offline: bool,
    ) -> MonitorCycleSummary:
        now = datetime.now(timezone.utc)
        new_devices = 0
        came_online = 0
        went_offline = 0
        alerts_created = 0
        observed_ids: set[int] = set()

        with self._database.session() as session:
            for item in observations:
                device, created = self._upsert_device(session, item, now)
                was_online = bool(device.is_online)
                if created:
                    session.add(device)
                session.flush()
                observed_ids.add(device.id)

                if created:
                    new_devices += 1
                    self._add_event(
                        session,
                        now=now,
                        device=device,
                        event_type="device_discovered",
                        severity=RiskLevel.MEDIUM,
                        title="New device discovered",
                        message=f"A new device was observed at {device.ip}.",
                    )
                    if self._ensure_alert(
                        session,
                        now=now,
                        device=device,
                        category="unknown_device",
                        severity=RiskLevel.MEDIUM,
                        title="Unknown device detected",
                        message=(
                            f"{device.custom_name or device.hostname or device.ip} is new to the inventory. "
                            "Review it and mark it Trusted or Blocked."
                        ),
                    ):
                        alerts_created += 1
                elif not was_online:
                    came_online += 1
                    self._add_event(
                        session,
                        now=now,
                        device=device,
                        event_type="device_online",
                        severity=RiskLevel.LOW,
                        title="Device came online",
                        message=f"{device.custom_name or device.hostname or device.ip} is reachable again.",
                    )
                    if device.trust_status == DeviceTrust.UNKNOWN.value and self._ensure_alert(
                        session,
                        now=now,
                        device=device,
                        category="unknown_device",
                        severity=RiskLevel.MEDIUM,
                        title="Unknown device detected",
                        message=(
                            f"{device.custom_name or device.hostname or device.ip} is online and still requires "
                            "trust review."
                        ),
                    ):
                        alerts_created += 1

                device.is_online = True
                if created or not was_online or device.last_state_change_at is None:
                    device.last_state_change_at = now
                device.last_seen_at = now
                device.ip = item.ip
                normalized_mac = self._normalize_mac(item.mac_address)
                if item.hostname:
                    device.hostname = item.hostname
                if normalized_mac:
                    device.mac_address = normalized_mac
                if item.vendor:
                    device.vendor = item.vendor
                if item.methods:
                    device.discovery_methods = ",".join(item.methods)
                if item.latency_ms is not None:
                    device.last_latency_ms = str(round(item.latency_ms, 2))
                device.missed_cycles = 0

                if device.trust_status == DeviceTrust.BLOCKED.value and (created or not was_online):
                    if self._ensure_alert(
                        session,
                        now=now,
                        device=device,
                        category="blocked_device_online",
                        severity=RiskLevel.HIGH,
                        title="Blocked device is online",
                        message=(
                            f"{device.custom_name or device.hostname or device.ip} is marked Blocked "
                            "but is currently reachable."
                        ),
                    ):
                        alerts_created += 1

            if mark_missing_offline and target:
                for device in session.scalars(select(DeviceORM).where(DeviceORM.is_online.is_(True))):
                    if device.id in observed_ids or not self._ip_in_target(device.ip, target):
                        continue
                    device.missed_cycles = int(device.missed_cycles or 0) + 1
                    if device.missed_cycles < 2:
                        continue
                    device.is_online = False
                    device.last_state_change_at = now
                    went_offline += 1
                    self._add_event(
                        session,
                        now=now,
                        device=device,
                        event_type="device_offline",
                        severity=RiskLevel.LOW,
                        title="Device went offline",
                        message=(
                            f"{device.custom_name or device.hostname or device.ip} was not reachable "
                            "in two consecutive monitoring cycles."
                        ),
                    )
                    session.execute(
                        update(AlertORM)
                        .where(
                            AlertORM.device_id == device.id,
                            AlertORM.category == "blocked_device_online",
                            AlertORM.acknowledged.is_(False),
                        )
                        .values(acknowledged=True, acknowledged_at=now)
                    )

            session.commit()

        return MonitorCycleSummary(
            discovered=len(observations),
            new_devices=new_devices,
            came_online=came_online,
            went_offline=went_offline,
            alerts_created=alerts_created,
            completed_at=now,
        )

    def _upsert_device(
        self,
        session: Session,
        item: DeviceObservation,
        now: datetime,
    ) -> tuple[DeviceORM, bool]:
        mac = self._normalize_mac(item.mac_address)
        identity = mac or item.ip
        device = session.scalar(select(DeviceORM).where(DeviceORM.identity_key == identity))

        if device is None and mac:
            # Upgrade an older IP-only identity when ARP/OUI data becomes available.
            device = session.scalar(
                select(DeviceORM)
                .where(DeviceORM.ip == item.ip, DeviceORM.mac_address.is_(None))
                .order_by(DeviceORM.last_seen_at.desc())
                .limit(1)
            )
            if device is not None:
                device.identity_key = identity
                device.mac_address = mac
        elif device is None:
            # A previously MAC-identified device can still be rediscovered while
            # the OS ARP cache is cold. Reuse the most recent record for this IP
            # instead of creating an immediate duplicate.
            device = session.scalar(
                select(DeviceORM)
                .where(DeviceORM.ip == item.ip)
                .order_by(DeviceORM.last_seen_at.desc())
                .limit(1)
            )

        if device is None:
            return (
                DeviceORM(
                    identity_key=identity,
                    first_seen_at=now,
                    last_seen_at=now,
                    ip=item.ip,
                    hostname=item.hostname,
                    mac_address=mac,
                    vendor=item.vendor,
                    discovery_methods=",".join(item.methods) or None,
                    trust_status=DeviceTrust.UNKNOWN.value,
                    is_online=False,
                    last_state_change_at=now,
                ),
                True,
            )
        return device, False

    def list_devices(
        self,
        limit: int = 5000,
        *,
        search: str = "",
        trust: DeviceTrust | None = None,
        online: bool | None = None,
    ) -> list[DeviceRecord]:
        statement = select(DeviceORM)
        if search.strip():
            pattern = f"%{search.strip()}%"
            statement = statement.where(
                or_(
                    DeviceORM.ip.ilike(pattern),
                    DeviceORM.hostname.ilike(pattern),
                    DeviceORM.mac_address.ilike(pattern),
                    DeviceORM.vendor.ilike(pattern),
                    DeviceORM.custom_name.ilike(pattern),
                )
            )
        if trust is not None:
            statement = statement.where(DeviceORM.trust_status == trust.value)
        if online is not None:
            statement = statement.where(DeviceORM.is_online.is_(online))
        statement = statement.order_by(DeviceORM.is_online.desc(), DeviceORM.last_seen_at.desc()).limit(limit)
        with self._database.session() as session:
            return [self._device_to_domain(item) for item in session.scalars(statement).all()]

    def get_device(self, device_id: int) -> DeviceRecord | None:
        with self._database.session() as session:
            device = session.get(DeviceORM, device_id)
            return self._device_to_domain(device) if device else None

    def update_device(
        self,
        device_id: int,
        *,
        custom_name: str,
        trust_status: DeviceTrust,
        notes: str,
    ) -> DeviceRecord:
        now = datetime.now(timezone.utc)
        with self._database.session() as session:
            device = session.get(DeviceORM, device_id)
            if device is None:
                raise ValueError("Device was not found")
            old_trust = DeviceTrust(device.trust_status or DeviceTrust.UNKNOWN.value)
            device.custom_name = custom_name.strip() or None
            device.notes = notes.strip() or None
            device.trust_status = trust_status.value

            if old_trust != trust_status:
                self._add_event(
                    session,
                    now=now,
                    device=device,
                    event_type="trust_status_changed",
                    severity=RiskLevel.LOW if trust_status == DeviceTrust.TRUSTED else RiskLevel.MEDIUM,
                    title="Device trust status changed",
                    message=f"Trust status changed from {old_trust.value} to {trust_status.value}.",
                )
                if trust_status in {DeviceTrust.TRUSTED, DeviceTrust.BLOCKED}:
                    session.execute(
                        update(AlertORM)
                        .where(
                            AlertORM.device_id == device.id,
                            AlertORM.category == "unknown_device",
                            AlertORM.acknowledged.is_(False),
                        )
                        .values(acknowledged=True, acknowledged_at=now)
                    )

                if trust_status != DeviceTrust.BLOCKED:
                    session.execute(
                        update(AlertORM)
                        .where(
                            AlertORM.device_id == device.id,
                            AlertORM.category == "blocked_device_online",
                            AlertORM.acknowledged.is_(False),
                        )
                        .values(acknowledged=True, acknowledged_at=now)
                    )

                if trust_status == DeviceTrust.BLOCKED and device.is_online:
                    self._ensure_alert(
                        session,
                        now=now,
                        device=device,
                        category="blocked_device_online",
                        severity=RiskLevel.HIGH,
                        title="Blocked device is online",
                        message=f"{device.custom_name or device.hostname or device.ip} is marked Blocked and reachable.",
                    )
                elif trust_status == DeviceTrust.UNKNOWN:
                    self._ensure_alert(
                        session,
                        now=now,
                        device=device,
                        category="unknown_device",
                        severity=RiskLevel.MEDIUM,
                        title="Unknown device detected",
                        message=(
                            f"{device.custom_name or device.hostname or device.ip} requires trust review. "
                            "Mark it Trusted or Blocked when verified."
                        ),
                    )
            session.commit()
            return self._device_to_domain(device)

    def device_counts(self) -> dict[str, int]:
        with self._database.session() as session:
            total = int(session.scalar(select(func.count(DeviceORM.id))) or 0)
            online = int(
                session.scalar(select(func.count(DeviceORM.id)).where(DeviceORM.is_online.is_(True))) or 0
            )
            trusted = int(
                session.scalar(
                    select(func.count(DeviceORM.id)).where(DeviceORM.trust_status == DeviceTrust.TRUSTED.value)
                )
                or 0
            )
            blocked = int(
                session.scalar(
                    select(func.count(DeviceORM.id)).where(DeviceORM.trust_status == DeviceTrust.BLOCKED.value)
                )
                or 0
            )
            unknown = int(
                session.scalar(
                    select(func.count(DeviceORM.id)).where(DeviceORM.trust_status == DeviceTrust.UNKNOWN.value)
                )
                or 0
            )
            alerts = int(
                session.scalar(
                    select(func.count(AlertORM.id)).where(AlertORM.acknowledged.is_(False))
                )
                or 0
            )
        return {
            "total": total,
            "online": online,
            "offline": max(0, total - online),
            "trusted": trusted,
            "blocked": blocked,
            "unknown": unknown,
            "alerts": alerts,
        }

    # ------------------------------------------------------------------
    # Event and alert log
    # ------------------------------------------------------------------
    def list_events(self, limit: int = 1000) -> list[EventRecord]:
        statement = (
            select(EventORM, DeviceORM)
            .outerjoin(DeviceORM, EventORM.device_id == DeviceORM.id)
            .order_by(EventORM.id.desc())
            .limit(limit)
        )
        with self._database.session() as session:
            rows = session.execute(statement).all()
        return [
            EventRecord(
                id=event.id,
                created_at=event.created_at,
                event_type=event.event_type,
                severity=RiskLevel(event.severity or "low"),
                title=event.title,
                message=event.message,
                device_id=event.device_id,
                device_name=(device.custom_name or device.hostname or device.ip) if device else None,
                ip=event.ip,
            )
            for event, device in rows
        ]

    def list_alerts(self, limit: int = 1000, *, include_acknowledged: bool = False) -> list[AlertRecord]:
        statement = select(AlertORM, DeviceORM).outerjoin(DeviceORM, AlertORM.device_id == DeviceORM.id)
        if not include_acknowledged:
            statement = statement.where(AlertORM.acknowledged.is_(False))
        statement = statement.order_by(AlertORM.acknowledged.asc(), AlertORM.id.desc()).limit(limit)
        with self._database.session() as session:
            rows = session.execute(statement).all()
        return [
            AlertRecord(
                id=alert.id,
                created_at=alert.created_at,
                severity=RiskLevel(alert.severity),
                category=alert.category,
                title=alert.title,
                message=alert.message,
                device_id=alert.device_id,
                device_name=(device.custom_name or device.hostname or device.ip) if device else None,
                ip=alert.ip,
                acknowledged=bool(alert.acknowledged),
                acknowledged_at=alert.acknowledged_at,
            )
            for alert, device in rows
        ]

    def acknowledge_alert(self, alert_id: int) -> None:
        now = datetime.now(timezone.utc)
        with self._database.session() as session:
            alert = session.get(AlertORM, alert_id)
            if alert is None:
                raise ValueError("Alert was not found")
            alert.acknowledged = True
            alert.acknowledged_at = now
            session.commit()

    def acknowledge_all_alerts(self) -> int:
        now = datetime.now(timezone.utc)
        with self._database.session() as session:
            result = session.execute(
                update(AlertORM)
                .where(AlertORM.acknowledged.is_(False))
                .values(acknowledged=True, acknowledged_at=now)
            )
            session.commit()
            return int(result.rowcount or 0)

    def clear_acknowledged_alerts(self) -> int:
        with self._database.session() as session:
            result = session.execute(delete(AlertORM).where(AlertORM.acknowledged.is_(True)))
            session.commit()
            return int(result.rowcount or 0)

    @staticmethod
    def _add_event(
        session: Session,
        *,
        now: datetime,
        device: DeviceORM,
        event_type: str,
        severity: RiskLevel,
        title: str,
        message: str,
    ) -> None:
        session.add(
            EventORM(
                created_at=now,
                event_type=event_type,
                severity=severity.value,
                title=title,
                message=message,
                device_id=device.id,
                ip=device.ip,
            )
        )

    @staticmethod
    def _ensure_alert(
        session: Session,
        *,
        now: datetime,
        device: DeviceORM,
        category: str,
        severity: RiskLevel,
        title: str,
        message: str,
    ) -> bool:
        existing = session.scalar(
            select(AlertORM).where(
                AlertORM.device_id == device.id,
                AlertORM.category == category,
                AlertORM.acknowledged.is_(False),
            )
        )
        if existing is not None:
            return False
        session.add(
            AlertORM(
                created_at=now,
                severity=severity.value,
                category=category,
                title=title,
                message=message,
                device_id=device.id,
                ip=device.ip,
                acknowledged=False,
            )
        )
        return True

    @staticmethod
    def _normalize_mac(value: str | None) -> str | None:
        if not value:
            return None
        compact = "".join(ch for ch in value.upper() if ch in "0123456789ABCDEF")
        if len(compact) != 12:
            return None
        return ":".join(compact[index : index + 2] for index in range(0, 12, 2))

    @staticmethod
    def _ip_in_target(ip: str, target: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
            if "/" in target:
                return address in ipaddress.ip_network(target, strict=False)
            return address == ipaddress.ip_address(target)
        except ValueError:
            return False

    @staticmethod
    def _device_to_domain(device: DeviceORM) -> DeviceRecord:
        try:
            latency = float(device.last_latency_ms) if device.last_latency_ms else None
        except ValueError:
            latency = None
        return DeviceRecord(
            id=device.id,
            identity_key=device.identity_key,
            first_seen_at=device.first_seen_at,
            last_seen_at=device.last_seen_at,
            ip=device.ip,
            hostname=device.hostname,
            mac_address=device.mac_address,
            vendor=device.vendor,
            discovery_methods=tuple((device.discovery_methods or "").split(","))
            if device.discovery_methods
            else (),
            trust_status=DeviceTrust(device.trust_status or DeviceTrust.UNKNOWN.value),
            custom_name=device.custom_name,
            notes=device.notes,
            is_online=bool(device.is_online),
            last_latency_ms=latency,
            last_state_change_at=device.last_state_change_at,
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
