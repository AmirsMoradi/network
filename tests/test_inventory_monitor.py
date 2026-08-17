from pathlib import Path

from app.database.session import Database
from app.domain.models import DeviceObservation, DeviceTrust
from app.services.history import HistoryService


def observation(ip: str = "192.168.50.10", mac: str = "AA-BB-CC-11-22-33") -> DeviceObservation:
    return DeviceObservation(
        ip=ip,
        hostname="test-device",
        mac_address=mac,
        vendor="Example Vendor",
        methods=("icmp",),
        latency_ms=3.5,
    )


def test_new_device_alert_trust_and_offline_transition(tmp_path: Path) -> None:
    database = Database(tmp_path / "surnet.db")
    database.initialize()
    history = HistoryService(database)

    summary = history.save_discovery([observation()])
    assert summary.new_devices == 1
    assert summary.alerts_created == 1
    devices = history.list_devices()
    assert len(devices) == 1
    assert devices[0].is_online is True
    assert devices[0].trust_status == DeviceTrust.UNKNOWN
    assert devices[0].mac_address == "AA:BB:CC:11:22:33"
    assert len(history.list_alerts()) == 1

    history.update_device(
        devices[0].id,
        custom_name="Office Laptop",
        trust_status=DeviceTrust.TRUSTED,
        notes="Known device",
    )
    updated = history.get_device(devices[0].id)
    assert updated is not None
    assert updated.display_name == "Office Laptop"
    assert updated.trust_status == DeviceTrust.TRUSTED
    assert history.list_alerts() == []

    first_miss = history.record_monitor_cycle([], "192.168.50.0/24")
    assert first_miss.went_offline == 0
    assert history.get_device(devices[0].id).is_online is True  # type: ignore[union-attr]

    second_miss = history.record_monitor_cycle([], "192.168.50.0/24")
    assert second_miss.went_offline == 1
    assert history.get_device(devices[0].id).is_online is False  # type: ignore[union-attr]
    assert any(event.event_type == "device_offline" for event in history.list_events())


def test_blocked_device_alerts_when_marked_and_when_it_returns(tmp_path: Path) -> None:
    database = Database(tmp_path / "surnet.db")
    database.initialize()
    history = HistoryService(database)
    history.save_discovery([observation()])
    device = history.list_devices()[0]
    history.acknowledge_all_alerts()

    history.update_device(
        device.id,
        custom_name="Blocked test",
        trust_status=DeviceTrust.BLOCKED,
        notes="",
    )
    alerts = history.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].category == "blocked_device_online"
    history.acknowledge_all_alerts()

    history.record_monitor_cycle([], "192.168.50.0/24")
    history.record_monitor_cycle([], "192.168.50.0/24")
    assert history.get_device(device.id).is_online is False  # type: ignore[union-attr]

    summary = history.record_monitor_cycle([observation()], "192.168.50.0/24")
    assert summary.came_online == 1
    alerts = history.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].category == "blocked_device_online"


def test_cold_arp_cycle_reuses_mac_identity_and_preserves_enrichment(tmp_path: Path) -> None:
    database = Database(tmp_path / "surnet.db")
    database.initialize()
    history = HistoryService(database)
    history.save_discovery([observation()])
    original = history.list_devices()[0]

    without_arp = DeviceObservation(
        ip=original.ip,
        hostname=None,
        mac_address=None,
        vendor=None,
        methods=("tcp:443",),
        latency_ms=None,
    )
    summary = history.record_monitor_cycle([without_arp], "192.168.50.0/24")
    devices = history.list_devices()

    assert summary.new_devices == 0
    assert len(devices) == 1
    assert devices[0].id == original.id
    assert devices[0].mac_address == "AA:BB:CC:11:22:33"
    assert devices[0].hostname == "test-device"
    assert devices[0].vendor == "Example Vendor"
    assert devices[0].last_latency_ms == 3.5


def test_invalid_mac_does_not_become_device_identity(tmp_path: Path) -> None:
    database = Database(tmp_path / "surnet.db")
    database.initialize()
    history = HistoryService(database)
    bad = observation(mac="not-a-mac")
    history.save_discovery([bad])
    device = history.list_devices()[0]
    assert device.identity_key == bad.ip
    assert device.mac_address is None


def test_trust_review_resolves_stale_alert_categories(tmp_path: Path) -> None:
    database = Database(tmp_path / "surnet.db")
    database.initialize()
    history = HistoryService(database)
    history.save_discovery([observation()])
    device = history.list_devices()[0]
    assert [alert.category for alert in history.list_alerts()] == ["unknown_device"]

    history.update_device(
        device.id,
        custom_name="Rejected device",
        trust_status=DeviceTrust.BLOCKED,
        notes="Not authorized",
    )
    assert [alert.category for alert in history.list_alerts()] == ["blocked_device_online"]

    history.record_monitor_cycle([], "192.168.50.0/24")
    history.record_monitor_cycle([], "192.168.50.0/24")
    assert history.list_alerts() == []

    history.update_device(
        device.id,
        custom_name="Needs review again",
        trust_status=DeviceTrust.UNKNOWN,
        notes="",
    )
    assert [alert.category for alert in history.list_alerts()] == ["unknown_device"]


def test_unknown_device_realerts_only_after_returning_online(tmp_path: Path) -> None:
    database = Database(tmp_path / "surnet.db")
    database.initialize()
    history = HistoryService(database)
    history.save_discovery([observation()])
    device = history.list_devices()[0]
    history.acknowledge_all_alerts()

    # Remaining online does not recreate a manually acknowledged review alert.
    history.record_monitor_cycle([observation()], "192.168.50.0/24")
    assert history.list_alerts() == []

    history.record_monitor_cycle([], "192.168.50.0/24")
    history.record_monitor_cycle([], "192.168.50.0/24")
    assert history.get_device(device.id).is_online is False  # type: ignore[union-attr]

    summary = history.record_monitor_cycle([observation()], "192.168.50.0/24")
    assert summary.alerts_created == 1
    assert [alert.category for alert in history.list_alerts()] == ["unknown_device"]
