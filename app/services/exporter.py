from __future__ import annotations

import csv
import json
from pathlib import Path

from app.domain.models import ScanResult


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
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

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
