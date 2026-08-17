from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

from app.core.config import APP_NAME

LOGGER = logging.getLogger(__name__)


class TrayService:
    """Small optional system-tray wrapper. It is intentionally lazy-imported."""

    def __init__(self, on_show: Callable[[], None], on_exit: Callable[[], None]) -> None:
        self._on_show = on_show
        self._on_exit = on_exit
        self._icon: Any | None = None

    @property
    def running(self) -> bool:
        return self._icon is not None

    def start(self) -> bool:
        if self._icon is not None:
            return True
        if os.name != "nt":
            return False
        try:
            import pystray
            from PIL import Image, ImageDraw

            image = Image.new("RGBA", (64, 64), (11, 18, 32, 255))
            draw = ImageDraw.Draw(image)
            draw.rounded_rectangle((8, 8, 56, 56), radius=12, fill=(59, 130, 246, 255))
            draw.ellipse((19, 19, 45, 45), outline=(255, 255, 255, 255), width=4)
            draw.line((32, 31, 32, 45), fill=(255, 255, 255, 255), width=4)
            menu = pystray.Menu(
                pystray.MenuItem("Show SurNet Guardian", lambda _icon, _item: self._on_show()),
                pystray.MenuItem("Exit", lambda _icon, _item: self._on_exit()),
            )
            self._icon = pystray.Icon("SurNetGuardian", image, APP_NAME, menu)
            self._icon.run_detached()
            return True
        except Exception:
            LOGGER.exception("System tray could not be started")
            self._icon = None
            return False

    def notify(self, title: str, message: str) -> None:
        icon = self._icon
        if icon is None:
            return
        try:
            icon.notify(message, title)
        except Exception:
            LOGGER.exception("Tray notification failed")

    def stop(self) -> None:
        icon = self._icon
        self._icon = None
        if icon is None:
            return
        try:
            icon.stop()
        except Exception:
            LOGGER.exception("System tray shutdown failed")
