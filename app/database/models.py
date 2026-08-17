from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanORM(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(128), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    hosts: Mapped[list[HostORM]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class HostORM(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scan: Mapped[ScanORM] = relationship(back_populates="hosts")
    ports: Mapped[list[PortORM]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )


class PortORM(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    service: Mapped[str] = mapped_column(String(64))
    host: Mapped[HostORM] = relationship(back_populates="ports")
