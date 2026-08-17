from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database.models import HostORM, PortORM, ScanORM
from app.database.session import Database
from app.domain.models import ScanResult


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
            host_orm = HostORM(ip=host.ip, hostname=host.hostname)
            for port in host.ports:
                host_orm.ports.append(PortORM(port=port.port, service=port.service))
            scan.hosts.append(host_orm)

        with self._database.session() as session:
            session.add(scan)
            session.commit()
            return scan.id

    def list_recent(self, limit: int = 100) -> list[ScanORM]:
        statement = (
            select(ScanORM)
            .options(selectinload(ScanORM.hosts).selectinload(HostORM.ports))
            .order_by(ScanORM.id.desc())
            .limit(limit)
        )
        with self._database.session() as session:
            return list(session.scalars(statement).all())
