from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import APP_DIR, DB_PATH
from app.database.models import Base


class Database:
    def __init__(self) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(f"sqlite:///{DB_PATH}", future=True)
        self._session_factory = sessionmaker(
            bind=self._engine,
            class_=Session,
            expire_on_commit=False,
        )

    def initialize(self) -> None:
        Base.metadata.create_all(self._engine)

    def session(self) -> Session:
        return self._session_factory()
