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
                    "ports": [
                        {
                            "port": port.port,
                            "service": port.service,
                            "latency_ms": port.latency_ms,
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
            writer.writerow(["ip", "hostname", "port", "service", "latency_ms"])
            for host in result.hosts:
                for port in host.ports:
                    writer.writerow(
                        [host.ip, host.hostname or "", port.port, port.service, port.latency_ms]
                    )
