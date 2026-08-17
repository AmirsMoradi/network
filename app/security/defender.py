from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


class WindowsDefenderCorrelator:
    """Correlate executable paths with Microsoft Defender detection resources.

    This is evidence of a Defender detection record, not proof that the file is
    currently active malware. The UI deliberately presents it as detection evidence.
    """

    def __init__(self) -> None:
        self._detected_paths = self._load_detected_paths()

    def detected(self, executable: str | None) -> bool:
        if not executable:
            return False
        normalized = self._normalize(executable)
        return normalized in self._detected_paths

    def _load_detected_paths(self) -> set[str]:
        if os.name != "nt":
            return set()
        script = (
            "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.Resources } | ForEach-Object { Write-Output $_ }"
        )
        try:
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            return set()
        if completed.returncode != 0:
            return set()

        paths: set[str] = set()
        for line in completed.stdout.splitlines():
            candidate = self._extract_path(line.strip())
            if candidate:
                paths.add(self._normalize(candidate))
        return paths

    @staticmethod
    def _extract_path(resource: str) -> str | None:
        # Defender resources commonly look like "file:_C:\path\sample.exe".
        match = re.search(r"(?i)file:_?(.*)$", resource)
        if match:
            return match.group(1).strip()
        if ":\\" in resource:
            return resource.strip()
        return None

    @staticmethod
    def _normalize(value: str) -> str:
        try:
            return str(Path(value).resolve()).casefold()
        except (OSError, RuntimeError):
            return os.path.abspath(value).casefold()
