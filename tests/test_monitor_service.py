from __future__ import annotations

from pathlib import Path

import pytest

from app.database.session import Database
from app.domain.models import DeviceObservation
from app.services.history import HistoryService
from app.services.monitor import NetworkMonitorService


class FakeDiscovery:
    async def discover(self, target: str, *, cancel_event: object | None = None) -> list[DeviceObservation]:
        del target, cancel_event
        return [
            DeviceObservation(
                ip="192.168.77.12",
                hostname="lab-device",
                mac_address="00-11-22-33-44-55",
                vendor=None,
                methods=("icmp",),
                latency_ms=2.0,
            )
        ]


class FakeVendor:
    def resolve(self, mac: str | None) -> str | None:
        return "Example Vendor" if mac else None


def test_run_once_persists_monitor_observation(tmp_path: Path) -> None:
    database = Database(tmp_path / "surnet.db")
    database.initialize()
    history = HistoryService(database)
    monitor = NetworkMonitorService(FakeDiscovery(), FakeVendor(), history)  # type: ignore[arg-type]

    summary = monitor.run_once("192.168.77.0/24")

    assert summary.discovered == 1
    assert summary.new_devices == 1
    device = history.list_devices()[0]
    assert device.vendor == "Example Vendor"
    assert device.is_online is True


def test_monitor_rejects_public_or_oversized_targets(tmp_path: Path) -> None:
    database = Database(tmp_path / "surnet.db")
    database.initialize()
    monitor = NetworkMonitorService(  # type: ignore[arg-type]
        FakeDiscovery(),
        FakeVendor(),
        HistoryService(database),
    )

    with pytest.raises(ValueError, match="private IPv4"):
        monitor.run_once("8.8.8.8")
    with pytest.raises(ValueError, match="4096-host"):
        monitor.start("10.0.0.0/8", 60)
