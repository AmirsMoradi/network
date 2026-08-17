import sqlite3
from pathlib import Path

from sqlalchemy import inspect

from app.database.session import Database


def test_v02_device_table_is_upgraded_additively(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            identity_key VARCHAR(128) UNIQUE,
            first_seen_at DATETIME NOT NULL,
            last_seen_at DATETIME NOT NULL,
            ip VARCHAR(64) NOT NULL,
            hostname VARCHAR(255),
            mac_address VARCHAR(32),
            vendor VARCHAR(255),
            discovery_methods VARCHAR(255)
        )
        """
    )
    connection.commit()
    connection.close()

    database = Database(path)
    database.initialize()
    columns = {item["name"] for item in inspect(database._engine).get_columns("devices")}  # noqa: SLF001
    assert {"trust_status", "custom_name", "notes", "is_online", "last_latency_ms", "last_state_change_at", "missed_cycles"} <= columns
    tables = set(inspect(database._engine).get_table_names())  # noqa: SLF001
    assert {"alerts", "events"} <= tables


def test_v03_device_indexes_exist_after_legacy_upgrade(tmp_path: Path) -> None:
    path = tmp_path / "legacy-index.db"
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            identity_key VARCHAR(128) UNIQUE,
            first_seen_at DATETIME NOT NULL,
            last_seen_at DATETIME NOT NULL,
            ip VARCHAR(64) NOT NULL,
            hostname VARCHAR(255),
            mac_address VARCHAR(32),
            vendor VARCHAR(255),
            discovery_methods VARCHAR(255)
        )
        """
    )
    connection.commit()
    connection.close()

    database = Database(path)
    database.initialize()
    index_names = {item["name"] for item in inspect(database._engine).get_indexes("devices")}  # noqa: SLF001
    assert {
        "ix_devices_trust_status",
        "ix_devices_is_online",
        "ix_devices_mac_address",
        "ix_devices_last_seen_at",
    } <= index_names
