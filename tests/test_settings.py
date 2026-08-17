from pathlib import Path

from app.services.settings import AppSettings, SettingsService


def test_settings_round_trip_and_normalization(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    service = SettingsService(path)
    settings = AppSettings(
        theme="LIGHT",
        auto_monitor=True,
        discovery_target=" 192.168.1.0/24 ",
        monitor_interval_seconds=2,
        notifications_enabled=False,
        minimize_to_tray=False,
        start_with_windows=True,
    )
    service.save(settings)
    loaded = service.load()
    assert loaded.theme == "light"
    assert loaded.discovery_target == "192.168.1.0/24"
    assert loaded.monitor_interval_seconds == 15
    assert loaded.auto_monitor is True
    assert loaded.notifications_enabled is False
    assert loaded.start_with_windows is True


def test_settings_load_handles_malformed_types(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        '{"theme": 42, "auto_monitor": "false", "notifications_enabled": "yes", '
        '"minimize_to_tray": "0", "monitor_interval_seconds": "999999"}',
        encoding="utf-8",
    )
    loaded = SettingsService(path).load()
    assert loaded.theme == "dark"
    assert loaded.auto_monitor is False
    assert loaded.notifications_enabled is True
    assert loaded.minimize_to_tray is False
    assert loaded.monitor_interval_seconds == 86_400

    path.write_text('["not", "a", "settings", "object"]', encoding="utf-8")
    assert SettingsService(path).load() == AppSettings()
