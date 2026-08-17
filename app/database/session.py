from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import APP_DIR, DB_PATH
from app.database.models import Base


class Database:
    def __init__(self, db_path: Path | None = None) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        path = db_path or DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(f"sqlite:///{path}", future=True)
        self._session_factory = sessionmaker(
            bind=self._engine,
            class_=Session,
            expire_on_commit=False,
        )

    def initialize(self) -> None:
        Base.metadata.create_all(self._engine)
        self._apply_additive_migrations()
        Base.metadata.create_all(self._engine)

    def session(self) -> Session:
        return self._session_factory()

    def _apply_additive_migrations(self) -> None:
        """Upgrade v0.1 SQLite databases without deleting scan history."""
        inspector = inspect(self._engine)
        if "hosts" in inspector.get_table_names():
            host_columns = {column["name"] for column in inspector.get_columns("hosts")}
            additions = {
                "mac_address": "VARCHAR(32)",
                "vendor": "VARCHAR(255)",
                "discovery_methods": "VARCHAR(255)",
            }
            self._add_missing_columns("hosts", host_columns, additions)

        inspector = inspect(self._engine)
        if "ports" in inspector.get_table_names():
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
