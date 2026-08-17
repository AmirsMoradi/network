from __future__ import annotations

import os
import subprocess
from functools import lru_cache


@lru_cache(maxsize=512)
def get_authenticode_status(executable: str | None) -> str | None:
    if os.name != "nt" or not executable:
        return None

    escaped = executable.replace("'", "''")
    script = (
        "$s=Get-AuthenticodeSignature -LiteralPath '"
        + escaped
        + "'; Write-Output $s.Status"
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
            timeout=3,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return "Unknown"

    status = completed.stdout.strip()
    return status or "Unknown"
