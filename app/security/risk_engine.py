from __future__ import annotations

import os
from pathlib import Path

from app.domain.models import RiskLevel

# These are indicators only; none is treated as proof of malware.
HIGH_ATTENTION_PORTS = {4444, 5555, 6667, 1337, 31337}
USER_WRITABLE_MARKERS = ("\\appdata\\", "\\temp\\", "\\downloads\\")


class ListenerRiskEngine:
    def score(
        self,
        *,
        port: int,
        local_ip: str,
        process_name: str,
        executable: str | None,
        signature_status: str | None,
        defender_detected: bool = False,
    ) -> tuple[int, RiskLevel, tuple[str, ...]]:
        score = 0
        reasons: list[str] = []

        if defender_detected:
            score += 100
            reasons.append("Executable is correlated with a Microsoft Defender detection record")

        if local_ip in {"0.0.0.0", "::"}:
            score += 15
            reasons.append("Listener is exposed on all local interfaces")

        if port in HIGH_ATTENTION_PORTS:
            score += 25
            reasons.append("Port is frequently used by remote-control or tunnelling tools")

        normalized_path = (executable or "").lower()
        if any(marker in normalized_path for marker in USER_WRITABLE_MARKERS):
            score += 35
            reasons.append("Executable is running from a user-writable location")

        if signature_status in {"NotSigned", "HashMismatch", "NotTrusted"}:
            score += 30
            reasons.append(f"Executable signature status: {signature_status}")
        elif signature_status == "UnknownError":
            score += 10
            reasons.append("Executable signature could not be validated")

        if executable and not self._is_expected_system_location(executable):
            if process_name.lower() in {"svchost.exe", "lsass.exe", "services.exe"}:
                score += 45
                reasons.append("System-like process name is running outside a trusted system path")

        score = min(score, 100)
        if score >= 70:
            level = RiskLevel.CRITICAL
        elif score >= 45:
            level = RiskLevel.HIGH
        elif score >= 20:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        return score, level, tuple(reasons)

    @staticmethod
    def _is_expected_system_location(executable: str) -> bool:
        if os.name != "nt":
            return True
        windows = Path(os.environ.get("WINDIR", r"C:\Windows")).resolve()
        try:
            return Path(executable).resolve().is_relative_to(windows)
        except (OSError, RuntimeError):
            return False
