from __future__ import annotations

from datetime import datetime, timezone

from app.database.session import Database
from app.domain.models import HostResult, PortResult, ScanResult, ServiceFingerprint
from app.services.history import HistoryService


def _scan(port: int, version: str) -> ScanResult:
    return ScanResult(
        target="192.168.1.10",
        hosts=[
            HostResult(
                ip="192.168.1.10",
                ports=[
                    PortResult(
                        port=port,
                        service="https" if port == 443 else "http",
                        fingerprint=ServiceFingerprint(product="nginx", version=version),
                    )
                ],
            )
        ],
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def test_compare_scans_detects_port_changes(tmp_path) -> None:
    database = Database(tmp_path / "history.sqlite3")
    database.initialize()
    history = HistoryService(database)
    older = history.save_scan(_scan(80, "1.24.0"))
    newer = history.save_scan(_scan(443, "1.25.0"))

    diff = history.compare_scans(older, newer)

    assert diff.new_ports == ("192.168.1.10:443/https",)
    assert diff.closed_ports == ("192.168.1.10:80/http",)
