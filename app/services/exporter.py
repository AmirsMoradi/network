from __future__ import annotations

import csv
import json
from pathlib import Path

from app.domain.models import AlertRecord, DeviceRecord, EventRecord, ScanResult


class ExportService:
    def export_json(self, result: ScanResult, path: Path) -> None:
        payload = {
            "target": result.target,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "hosts": [
                {
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "mac_address": host.mac_address,
                    "vendor": host.vendor,
                    "discovery_methods": list(host.discovery_methods),
                    "ports": [
                        {
                            "port": port.port,
                            "service": port.service,
                            "latency_ms": port.latency_ms,
                            "risk_score": port.risk_score,
                            "risk_level": port.risk_level.value,
                            "fingerprint": {
                                "product": port.fingerprint.product,
                                "version": port.fingerprint.version,
                                "banner": port.fingerprint.banner,
                                "tls_version": port.fingerprint.tls_version,
                                "tls_cipher": port.fingerprint.tls_cipher,
                                "certificate_expires_at": (
                                    port.fingerprint.certificate_expires_at.isoformat()
                                    if port.fingerprint.certificate_expires_at
                                    else None
                                ),
                                "certificate_subject": port.fingerprint.certificate_subject,
                            },
                            "findings": [
                                {
                                    "type": finding.finding_type,
                                    "title": finding.title,
                                    "severity": finding.severity.value,
                                    "score": finding.score,
                                    "evidence": finding.evidence,
                                    "recommendation": finding.recommendation,
                                    "cve_id": finding.cve_id,
                                    "known_exploited": finding.known_exploited,
                                }
                                for finding in port.findings
                            ],
                        }
                        for port in host.ports
                    ],
                }
                for host in result.hosts
            ],
        }
        self._write_json(path, payload)

    def export_csv(self, result: ScanResult, path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "ip",
                    "hostname",
                    "port",
                    "service",
                    "product",
                    "version",
                    "tls_version",
                    "risk_score",
                    "risk_level",
                    "finding_count",
                ]
            )
            for host in result.hosts:
                for port in host.ports:
                    writer.writerow(
                        [
                            host.ip,
                            host.hostname or "",
                            port.port,
                            port.service,
                            port.fingerprint.product or "",
                            port.fingerprint.version or "",
                            port.fingerprint.tls_version or "",
                            port.risk_score,
                            port.risk_level.value,
                            len(port.findings),
                        ]
                    )

    def export_devices_json(self, devices: list[DeviceRecord], path: Path) -> None:
        payload = [
            {
                "id": item.id,
                "display_name": item.display_name,
                "custom_name": item.custom_name,
                "ip": item.ip,
                "hostname": item.hostname,
                "mac_address": item.mac_address,
                "vendor": item.vendor,
                "trust_status": item.trust_status.value,
                "online": item.is_online,
                "first_seen_at": item.first_seen_at.isoformat(),
                "last_seen_at": item.last_seen_at.isoformat(),
                "last_latency_ms": item.last_latency_ms,
                "discovery_methods": list(item.discovery_methods),
                "notes": item.notes,
            }
            for item in devices
        ]
        self._write_json(path, payload)

    def export_devices_csv(self, devices: list[DeviceRecord], path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "id",
                    "name",
                    "status",
                    "trust",
                    "ip",
                    "hostname",
                    "mac",
                    "vendor",
                    "first_seen",
                    "last_seen",
                    "latency_ms",
                    "notes",
                ]
            )
            for item in devices:
                writer.writerow(
                    [
                        item.id,
                        item.display_name,
                        "online" if item.is_online else "offline",
                        item.trust_status.value,
                        item.ip,
                        item.hostname or "",
                        item.mac_address or "",
                        item.vendor or "",
                        item.first_seen_at.isoformat(),
                        item.last_seen_at.isoformat(),
                        item.last_latency_ms if item.last_latency_ms is not None else "",
                        item.notes or "",
                    ]
                )

    def export_events_json(self, events: list[EventRecord], path: Path) -> None:
        self._write_json(
            path,
            [
                {
                    "id": item.id,
                    "created_at": item.created_at.isoformat(),
                    "type": item.event_type,
                    "severity": item.severity.value,
                    "title": item.title,
                    "message": item.message,
                    "device_id": item.device_id,
                    "device_name": item.device_name,
                    "ip": item.ip,
                }
                for item in events
            ],
        )

    def export_events_csv(self, events: list[EventRecord], path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(["id", "created_at", "severity", "type", "device", "ip", "title", "message"])
            for item in events:
                writer.writerow(
                    [
                        item.id,
                        item.created_at.isoformat(),
                        item.severity.value,
                        item.event_type,
                        item.device_name or "",
                        item.ip or "",
                        item.title,
                        item.message,
                    ]
                )

    def export_alerts_json(self, alerts: list[AlertRecord], path: Path) -> None:
        self._write_json(
            path,
            [
                {
                    "id": item.id,
                    "created_at": item.created_at.isoformat(),
                    "severity": item.severity.value,
                    "category": item.category,
                    "title": item.title,
                    "message": item.message,
                    "device_id": item.device_id,
                    "device_name": item.device_name,
                    "ip": item.ip,
                    "acknowledged": item.acknowledged,
                    "acknowledged_at": (
                        item.acknowledged_at.isoformat() if item.acknowledged_at else None
                    ),
                }
                for item in alerts
            ],
        )

    def export_alerts_csv(self, alerts: list[AlertRecord], path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "id",
                    "created_at",
                    "severity",
                    "category",
                    "device",
                    "ip",
                    "title",
                    "message",
                    "acknowledged",
                ]
            )
            for item in alerts:
                writer.writerow(
                    [
                        item.id,
                        item.created_at.isoformat(),
                        item.severity.value,
                        item.category,
                        item.device_name or "",
                        item.ip or "",
                        item.title,
                        item.message,
                        item.acknowledged,
                    ]
                )

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
