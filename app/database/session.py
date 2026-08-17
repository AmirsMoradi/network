from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import DB_PATH
from app.database.models import Base


class Database:
    def __init__(self, db_path: Path | None = None) -> None:
        path = db_path or DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(
            f"sqlite:///{path}",
            future=True,
            connect_args={"timeout": 10},
        )
        self._configure_sqlite()
        self._session_factory = sessionmaker(
            bind=self._engine,
            class_=Session,
            expire_on_commit=False,
        )


    def _configure_sqlite(self) -> None:
        """Configure SQLite for safe UI/background-monitor concurrency."""

        @event.listens_for(self._engine, "connect")
        def set_sqlite_pragmas(dbapi_connection: object, _connection_record: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=10000")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            finally:
                cursor.close()

    def initialize(self) -> None:
        # Create any brand-new tables first, then add columns needed by older installs.
        Base.metadata.create_all(self._engine)
        self._apply_additive_migrations()
        Base.metadata.create_all(self._engine)
        self._ensure_indexes()

    def session(self) -> Session:
        return self._session_factory()

    def _apply_additive_migrations(self) -> None:
        """Upgrade existing SQLite databases without deleting user history."""
        inspector = inspect(self._engine)
        tables = set(inspector.get_table_names())

        if "hosts" in tables:
            host_columns = {column["name"] for column in inspector.get_columns("hosts")}
            additions = {
                "mac_address": "VARCHAR(32)",
                "vendor": "VARCHAR(255)",
                "discovery_methods": "VARCHAR(255)",
            }
            self._add_missing_columns("hosts", host_columns, additions)

        inspector = inspect(self._engine)
        if "ports" in set(inspector.get_table_names()):
            port_columns = {column["name"] for column in inspector.get_columns("ports")}
            additions = {
                "latency_ms": "VARCHAR(32)",
                "product": "VARCHAR(255)",
                "version": "VARCHAR(128)",
                "banner": "TEXT",
                "tls_version": "VARCHAR(32)",
                "tls_cipher": "VARCHAR(128)",
                "certificate_expires_at": "DATETIME",
                "certificate_subject": "VARCHAR(512)",
                "risk_score": "INTEGER DEFAULT 0",
                "risk_level": "VARCHAR(16) DEFAULT 'low'",
            }
            self._add_missing_columns("ports", port_columns, additions)

        inspector = inspect(self._engine)
        if "devices" in set(inspector.get_table_names()):
            device_columns = {column["name"] for column in inspector.get_columns("devices")}
            additions = {
                "trust_status": "VARCHAR(16) NOT NULL DEFAULT 'unknown'",
                "custom_name": "VARCHAR(255)",
                "notes": "TEXT",
                "is_online": "BOOLEAN NOT NULL DEFAULT 0",
                "last_latency_ms": "VARCHAR(32)",
                "last_state_change_at": "DATETIME",
                "missed_cycles": "INTEGER NOT NULL DEFAULT 0",
            }
            self._add_missing_columns("devices", device_columns, additions)

    def _ensure_indexes(self) -> None:
        """Create indexes introduced after older device tables were already present."""
        statements = (
            'CREATE INDEX IF NOT EXISTS "ix_devices_trust_status" ON "devices" ("trust_status")',
            'CREATE INDEX IF NOT EXISTS "ix_devices_is_online" ON "devices" ("is_online")',
            'CREATE INDEX IF NOT EXISTS "ix_devices_mac_address" ON "devices" ("mac_address")',
            'CREATE INDEX IF NOT EXISTS "ix_devices_last_seen_at" ON "devices" ("last_seen_at")',
        )
        inspector = inspect(self._engine)
        if "devices" not in set(inspector.get_table_names()):
            return
        with self._engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))

    def _add_missing_columns(
        self,
        table: str,
        existing_columns: set[str],
        additions: dict[str, str],
    ) -> None:
        with self._engine.begin() as connection:
            for name, definition in additions.items():
                if name in existing_columns:
                    continue
                connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}'))
