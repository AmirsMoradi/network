from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.core.config import SETTINGS_PATH


@dataclass(slots=True)
class AppSettings:
    theme: str = "dark"
    auto_monitor: bool = False
    discovery_target: str = ""
    monitor_interval_seconds: int = 60
    notifications_enabled: bool = True
    minimize_to_tray: bool = True
    start_with_windows: bool = False


class SettingsService:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or SETTINGS_PATH

    def load(self) -> AppSettings:
        try:
            payload: Any = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return AppSettings()
        if not isinstance(payload, dict):
            return AppSettings()

        defaults = asdict(AppSettings())
        values = {key: payload.get(key, value) for key, value in defaults.items()}
        try:
            settings = AppSettings(**values)
        except TypeError:
            return AppSettings()
        self._normalize(settings)
        return settings

    def save(self, settings: AppSettings) -> None:
        self._normalize(settings)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(asdict(settings), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary.replace(self._path)

    @staticmethod
    def _coerce_bool(value: object, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off", ""}:
                return False
        return default

    @classmethod
    def _normalize(cls, settings: AppSettings) -> None:
        settings.theme = str(settings.theme or "dark").lower().strip()
        if settings.theme not in {"dark", "light"}:
            settings.theme = "dark"
        try:
            interval = int(settings.monitor_interval_seconds)
        except (TypeError, ValueError):
            interval = 60
        settings.monitor_interval_seconds = min(86_400, max(15, interval))
        settings.discovery_target = str(settings.discovery_target or "").strip()
        settings.auto_monitor = cls._coerce_bool(settings.auto_monitor, False)
        settings.notifications_enabled = cls._coerce_bool(settings.notifications_enabled, True)
        settings.minimize_to_tray = cls._coerce_bool(settings.minimize_to_tray, True)
        settings.start_with_windows = cls._coerce_bool(settings.start_with_windows, False)
