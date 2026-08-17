from __future__ import annotations

import os
import subprocess
import sys

from app.core.config import APP_NAME


class StartupService:
    """Manage the current user's Windows startup entry (HKCU only)."""

    REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

    def is_supported(self) -> bool:
        return os.name == "nt"

    def is_enabled(self) -> bool:
        if not self.is_supported():
            return False
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REGISTRY_PATH) as key:
                value, _ = winreg.QueryValueEx(key, APP_NAME)
            return bool(value)
        except (OSError, ImportError):
            return False

    def set_enabled(self, enabled: bool) -> tuple[bool, str]:
        if not self.is_supported():
            return False, "Start with Windows is available only on Windows."
        try:
            import winreg

            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                self.REGISTRY_PATH,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                if enabled:
                    winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, self._command())
                else:
                    try:
                        winreg.DeleteValue(key, APP_NAME)
                    except FileNotFoundError:
                        pass
            return True, "Startup preference updated."
        except (OSError, ImportError) as exc:
            return False, f"Could not update Windows startup: {exc}"

    @staticmethod
    def _command() -> str:
        if getattr(sys, "frozen", False):
            return subprocess.list2cmdline([sys.executable])
        return subprocess.list2cmdline([sys.executable, "-m", "app.main"])
