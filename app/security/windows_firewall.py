from __future__ import annotations

import ctypes
import os
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FirewallActionResult:
    success: bool
    message: str


class WindowsFirewallService:
    RULE_PREFIX = "SurNet Guardian"

    def is_supported(self) -> bool:
        return os.name == "nt"

    def is_admin(self) -> bool:
        if os.name != "nt":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False

    def allow_inbound(self, port: int, protocol: str = "TCP") -> FirewallActionResult:
        return self._apply(port=port, protocol=protocol, action="Allow")

    def block_inbound(self, port: int, protocol: str = "TCP") -> FirewallActionResult:
        return self._apply(port=port, protocol=protocol, action="Block")

    def _apply(self, *, port: int, protocol: str, action: str) -> FirewallActionResult:
        self._validate(port, protocol)
        if not self.is_supported():
            return FirewallActionResult(False, "Windows Firewall control is Windows-only")
        if not self.is_admin():
            return FirewallActionResult(False, "Run SurNet Guardian as Administrator")

        rule_name = f"{self.RULE_PREFIX} {action} {protocol.upper()} {port}"
        safe_name = rule_name.replace("'", "''")
        allow_name = f"{self.RULE_PREFIX} Allow {protocol.upper()} {port}".replace("'", "''")
        block_name = f"{self.RULE_PREFIX} Block {protocol.upper()} {port}".replace("'", "''")
        script = (
            f"$allow='{allow_name}'; $block='{block_name}'; $name='{safe_name}'; "
            "Get-NetFirewallRule -DisplayName $allow -ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
            "Get-NetFirewallRule -DisplayName $block -ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
            f"New-NetFirewallRule -DisplayName $name -Direction Inbound "
            f"-Action {action} -Protocol {protocol.upper()} -LocalPort {port} "
            "-Profile Any | Out-Null"
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
                timeout=8,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return FirewallActionResult(False, f"Firewall command failed: {exc}")

        if completed.returncode != 0:
            error = completed.stderr.strip() or "Windows Firewall returned an error"
            return FirewallActionResult(False, error)
        verb = "allowed" if action == "Allow" else "blocked"
        return FirewallActionResult(True, f"Inbound {protocol.upper()} port {port} is now {verb}")

    @staticmethod
    def _validate(port: int, protocol: str) -> None:
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        if protocol.upper() not in {"TCP", "UDP"}:
            raise ValueError("Protocol must be TCP or UDP")
