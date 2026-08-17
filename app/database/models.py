from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
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
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    discovery_methods: Mapped[str | None] = mapped_column(String(255), nullable=True)
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
    latency_ms: Mapped[str | None] = mapped_column(String(32), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tls_cipher: Mapped[str | None] = mapped_column(String(128), nullable=True)
    certificate_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    certificate_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), default="low")
    host: Mapped[HostORM] = relationship(back_populates="ports")
    findings: Mapped[list[FindingORM]] = relationship(
        back_populates="port_observation",
        cascade="all, delete-orphan",
    )


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id", ondelete="CASCADE"), index=True)
    finding_type: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[int] = mapped_column(Integer)
    evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    port_observation: Mapped[PortORM] = relationship(back_populates="findings")


class DeviceORM(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identity_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    discovery_methods: Mapped[str | None] = mapped_column(String(255), nullable=True)
