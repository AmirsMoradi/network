from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from app.core.config import APP_DIR, LOG_PATH


def configure_logging() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if root.handlers:
        return

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(formatter)
    root.addHandler(handler)
